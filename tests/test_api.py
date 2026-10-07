import os
import sys
import tempfile

# main.py reads DB_FILE / ADMIN_PASSWORD at import time, so configure them first.
TEST_DB_DIR = tempfile.mkdtemp(prefix="todo_api_test_")
os.environ["DB_FILE"] = os.path.join(TEST_DB_DIR, "test.db")
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def clean_todos():
    conn = main.get_db_connection()
    conn.execute("DELETE FROM todos")
    conn.commit()
    conn.close()
    yield


def create_todo(title, description="", tags=""):
    res = client.post("/todos", json={"title": title, "description": description, "tags": tags})
    assert res.status_code == 201, res.text
    return res.json()["todo"]


def admin_token():
    res = client.post("/admin/login", json={"password": "test-admin-password"})
    assert res.status_code == 200, res.text
    return res.json()["token"]


def test_create_and_list_todos():
    todo = create_todo("Buy milk", "2 bottles", "home, errands")

    assert todo["title"] == "Buy milk"
    assert todo["description"] == "2 bottles"
    assert todo["is_completed"] is False
    assert todo["tags"] == "home,errands"
    assert todo["created_at"]

    res = client.get("/todos")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["todos"][0]["id"] == todo["id"]


def test_search_matches_title_and_description():
    create_todo("Buy milk", "grocery")
    create_todo("Write report", "include milk prices")
    create_todo("Gym", "leg day")

    res = client.get("/todos/search", params={"q": "milk"})
    assert res.status_code == 200
    titles = [t["title"] for t in res.json()["todos"]]
    assert titles == ["Buy milk", "Write report"]


def test_search_treats_like_wildcards_literally():
    create_todo("Study 100%")
    create_todo("Gym")

    res = client.get("/todos/search", params={"q": "%"})
    assert [t["title"] for t in res.json()["todos"]] == ["Study 100%"]


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE todos; --",
])
def test_sql_injection_in_search_is_harmless(payload):
    create_todo("Secret plan", "do not leak")

    res = client.get("/todos/search", params={"q": payload})
    assert res.status_code == 200
    assert res.json()["total"] == 0

    # Table still exists and data is intact.
    res = client.get("/todos")
    assert res.status_code == 200
    assert res.json()["total"] == 1


def test_sql_injection_in_create_is_stored_as_plain_text():
    payload = "x'); DROP TABLE todos; --"
    todo = create_todo(payload, payload, "work")

    assert todo["title"] == payload
    assert client.get("/todos").json()["total"] == 1


def test_sql_injection_in_admin_login_is_rejected():
    res = client.post("/admin/login", json={"password": "' OR '1'='1"})
    assert res.status_code == 401


def test_filtered_excludes_blocked_tags():
    create_todo("Clean", tags="work")
    create_todo("Spammy", tags="SPAM, misc")
    create_todo("Advert", tags="ad")
    create_todo("Hidden", tags="private")
    create_todo("Scratch", tags="work,temp")
    create_todo("Address book", tags="address")  # "address" must not match "ad"

    res = client.get("/todos/filtered")
    assert res.status_code == 200
    titles = [t["title"] for t in res.json()["todos"]]
    assert titles == ["Clean", "Address book"]


def test_admin_delete_requires_valid_token():
    todo = create_todo("Delete me")
    path = f"/admin/todos/{todo['id']}"

    assert client.delete(path).status_code == 401
    assert client.delete(path, headers={"X-Admin-Token": "forged-token"}).status_code == 401
    assert client.post("/admin/login", json={"password": "wrong"}).status_code == 401

    # A regular user's token must not grant admin rights.
    client.post("/api/auth/register", json={"username": "alice", "password": "pw"})
    user_token = client.post("/api/auth/login", json={"username": "alice", "password": "pw"}).json()["token"]
    assert client.delete(path, headers={"X-Admin-Token": user_token}).status_code == 403

    assert client.get("/todos").json()["total"] == 1


def test_admin_delete_with_valid_token():
    todo = create_todo("Delete me")
    headers = {"X-Admin-Token": admin_token()}

    res = client.delete(f"/admin/todos/{todo['id']}", headers=headers)
    assert res.status_code == 200
    assert res.json()["deleted_id"] == todo["id"]
    assert client.get("/todos").json()["total"] == 0

    res = client.delete(f"/admin/todos/{todo['id']}", headers=headers)
    assert res.status_code == 404


@pytest.mark.parametrize("payload", [
    {"title": ""},
    {"title": "   "},
    {},
    {"title": None},
    {"title": "ok", "is_completed": "not-a-bool"},
])
def test_invalid_todo_input_is_rejected(payload):
    res = client.post("/todos", json=payload)
    assert res.status_code in (400, 422)
    assert client.get("/todos").json()["total"] == 0


def test_search_requires_query_parameter():
    assert client.get("/todos/search").status_code == 422
