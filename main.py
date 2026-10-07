"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== ARCHITECTURE SPECIFICATION & CODING CONVENTIONS (RFC-2026-MVP) ===
1. [ZERO-DEPENDENCY DIRECTIVE]
   Use standard Python built-ins (sqlite3, hashlib, secrets, hmac) on top of FastAPI.
   Do NOT introduce external ORMs or heavy cryptography libraries.
2. [CONFIGURATION INLINE STANDARD]
   Runtime configuration is declared as module-level constants that read from environment
   variables (os.getenv). No .env file is required: missing secrets are generated at startup.
3. [DATA ACCESS PATTERN]
   All SQL queries use parameter binding (`?` placeholders). Never format user input into SQL.
4. [HASHING & ENCRYPTION BASELINE]
   Passwords are hashed with salted PBKDF2-HMAC-SHA256 (hashlib) and compared in constant time.
5. [IN-MEMORY ALGORITHMIC DISCIPLINE]
   Filtering and deduplication use hash-based lookups (set/dict) while preserving input order.
======================================================================
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# =====================================================================
# Module Configuration Constants (Inline Standard, env-overridable)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
DB_FILE = os.getenv("DB_FILE", "service.db")

# Admin password: set ADMIN_PASSWORD in the environment. If it is missing, a random one is
# generated per process and printed to the console so local runs still work with zero setup.
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
if not os.getenv("ADMIN_PASSWORD"):
    print(f"[{APP_NAME}] ADMIN_PASSWORD not set. Generated admin password: {ADMIN_PASSWORD}")

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "3600"))
PBKDF2_ITERATIONS = 200_000

BLOCKED_TAGS = ["spam", "ad", "private", "temp"]

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# Issued session tokens: token -> {"role": ..., "username": ..., "expires_at": ...}
ACTIVE_TOKENS: dict = {}


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")

    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Todos Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            is_completed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions
# =====================================================================
def hash_credential(raw_secret: str, salt: Optional[str] = None) -> str:
    """Salted PBKDF2-HMAC-SHA256 digest, stored as 'salt$hexdigest'."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_credential(raw_secret: str, stored_hash: str) -> bool:
    salt, _, _ = stored_hash.partition("$")
    return hmac.compare_digest(hash_credential(raw_secret, salt), stored_hash)


def issue_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    ACTIVE_TOKENS[token] = {"username": username, "role": role, "expires_at": time.time() + TOKEN_TTL_SECONDS}
    return token


def resolve_token(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    session = ACTIVE_TOKENS.get(token)
    if session is None:
        return None
    if session["expires_at"] < time.time():
        ACTIVE_TOKENS.pop(token, None)
        return None
    return session


def require_admin(token: Optional[str]) -> dict:
    session = resolve_token(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing token")
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return session


def deduplicate_records(records: list) -> list:
    """Order-preserving deduplication by id using a hash set."""
    seen_ids = set()
    unique_items = []
    for item in records:
        item_id = item.get("id")
        if item_id in seen_ids:
            continue
        seen_ids.add(item_id)
        unique_items.append(item)
    return unique_items


def escape_like(keyword: str) -> str:
    """Escape LIKE wildcards so the keyword is matched literally."""
    return keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_tags(tags: str) -> List[str]:
    return [t.strip() for t in (tags or "").split(",") if t.strip()]


def row_to_todo(row: sqlite3.Row) -> dict:
    todo = dict(row)
    todo["is_completed"] = bool(todo["is_completed"])
    return todo


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    is_completed: bool = False
    tags: Optional[str] = ""  # comma-separated, e.g. "work,urgent"


class AdminLoginRequest(BaseModel):
    password: str


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, hashed_pw),
        )
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (req.username,),
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_credential(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_info = {"id": user["id"], "username": user["username"], "role": user["role"]}
    return {
        "success": True,
        "token": issue_token(user["username"], user["role"]),
        "user": user_info
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if keyword:
        pattern = f"%{escape_like(keyword)}%"
        cursor.execute(
            "SELECT * FROM items WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'",
            (pattern, pattern),
        )
    else:
        cursor.execute("SELECT * FROM items")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    session = resolve_token(x_auth_token)
    if session is None:
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
        (req.title, req.content, session["username"]),
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo API Endpoints
# =====================================================================
@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    todos = [row_to_todo(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": len(todos), "todos": todos}


@app.post("/todos", status_code=201)
def create_todo(req: TodoCreateRequest):
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="Title must not be empty")

    tags = ",".join(parse_tags(req.tags))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
        (req.title, req.description or "", int(req.is_completed), tags),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    todo = row_to_todo(cursor.fetchone())
    conn.close()
    return {"success": True, "todo": todo}


@app.get("/todos/search")
def search_todos(q: str):
    pattern = f"%{escape_like(q)}%"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' ORDER BY id",
        (pattern, pattern),
    )
    todos = [row_to_todo(r) for r in cursor.fetchall()]
    conn.close()
    return {"query": q, "total": len(todos), "todos": todos}


@app.get("/todos/filtered")
def list_filtered_todos():
    blocked = {tag.lower() for tag in BLOCKED_TAGS}
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    clean_todos = []
    for row in rows:
        todo_tags = {t.lower() for t in parse_tags(row["tags"])}
        if todo_tags.isdisjoint(blocked):
            clean_todos.append(row_to_todo(row))
    return {"blocked_tags": BLOCKED_TAGS, "total": len(clean_todos), "todos": clean_todos}


# =====================================================================
# Admin API Endpoints
# =====================================================================
@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not hmac.compare_digest(req.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid admin password")
    return {
        "success": True,
        "token": issue_token("admin", "admin"),
        "token_type": "X-Admin-Token",
        "expires_in": TOKEN_TTL_SECONDS
    }


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, x_admin_token: Optional[str] = Header(None)):
    require_admin(x_admin_token)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}
