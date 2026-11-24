"""Custom security tests: app-specific flaws that SAST/SCA/secret scanners cannot see.

They assert the SECURE behaviour, so they pass only when the app is run hardened
(vulnerable=0) and fail the build if someone breaks an authorisation rule.
"""
import os
import uuid

os.environ.setdefault("vulnerable", "0")  # ponytail: hardened mode is the shipping config

import pytest
from config import vuln_app


@pytest.fixture(scope="module")
def client():
    c = vuln_app.app.test_client()
    c.get("/createdb")
    return c


def new_user(client, admin=None):
    name = "u" + uuid.uuid4().hex[:8]
    body = {"username": name, "password": "pw123", "email": f"{name}@mail.com"}
    if admin is not None:
        body["admin"] = admin
    client.post("/users/v1/register", json=body)
    return name, login(client, name, "pw123")


def login(client, name, pw):
    r = client.post("/users/v1/login", json={"username": name, "password": pw})
    return r.get_json().get("auth_token")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_bola_user_cannot_read_another_users_book_secret(client):
    alice, a_tok = new_user(client)
    _, b_tok = new_user(client)
    title = "book" + uuid.uuid4().hex[:6]
    client.post("/books/v1", json={"book_title": title, "secret": "ALICE-SECRET"}, headers=auth(a_tok))
    r = client.get(f"/books/v1/{title}", headers=auth(b_tok))
    assert "ALICE-SECRET" not in r.get_data(as_text=True), "BOLA: bob read alice's secret"


def test_mass_assignment_register_cannot_self_grant_admin(client):
    name, tok = new_user(client, admin=True)
    r = client.get("/me", headers=auth(tok))
    assert r.get_json()["data"]["admin"] is False, "Mass assignment: self-registered admin"


def test_user_cannot_change_another_users_password(client):
    alice, _ = new_user(client)
    _, b_tok = new_user(client)
    client.put(f"/users/v1/{alice}/password", json={"password": "hacked"}, headers=auth(b_tok))
    assert login(client, alice, "hacked") is None, "BFLA/IDOR: bob changed alice's password"


def test_login_does_not_reveal_whether_username_exists(client):
    ghost = client.post("/users/v1/login", json={"username": "nobody_" + uuid.uuid4().hex, "password": "x"})
    real, _ = new_user(client)
    wrong = client.post("/users/v1/login", json={"username": real, "password": "wrong"})
    assert ghost.get_data() == wrong.get_data(), "User enumeration via distinct login errors"
