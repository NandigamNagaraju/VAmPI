import os
import uuid

os.environ.setdefault("vulnerable", "0")

import pytest
from config import vuln_app


@pytest.fixture(scope="module")
def client():
    testClient = vuln_app.app.test_client()
    testClient.get("/createdb")
    return testClient


def login(client, username, password):
    response = client.post("/users/v1/login", json={"username": username, "password": password})
    return response.get_json().get("auth_token")


def createUser(client, admin=None):
    username = "user" + uuid.uuid4().hex[:8]
    body = {"username": username, "password": "pass123", "email": username + "@mail.com"}
    if admin is not None:
        body["admin"] = admin
    client.post("/users/v1/register", json=body)
    token = login(client, username, "pass123")
    return username, token


def authHeader(token):
    return {"Authorization": "Bearer " + token}


def testBookSecretIsOnlyVisibleToItsOwner(client):
    userAName, userAToken = createUser(client)
    userBName, userBToken = createUser(client)

    bookTitle = "book" + uuid.uuid4().hex[:6]
    client.post("/books/v1", json={"book_title": bookTitle, "secret": "USER-A-SECRET"}, headers=authHeader(userAToken))

    response = client.get("/books/v1/" + bookTitle, headers=authHeader(userBToken))
    assert "USER-A-SECRET" not in response.get_data(as_text=True), "User B can  read user A's secret"


def testNewUserCannotRegisterAsAdmin(client):
    userName, token = createUser(client, admin=True)

    response = client.get("/me", headers=authHeader(token))
    isAdmin = response.get_json()["data"]["admin"]
    assert isAdmin is False, "New user became admin by sending admin=true"
