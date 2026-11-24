# Custom security tests for VAmPI.
# These check business logic and authorisation rules that scanners cannot see.
# Each test checks the SECURE behaviour, so they pass when the app runs with
# vulnerable=0 and fail when someone breaks a rule (or runs with vulnerable=1).

import os
import uuid

# run the app in secure mode unless told otherwise
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


def testUserCannotReadAnotherUsersBookSecret(client):
    aliceName, aliceToken = createUser(client)
    bobName, bobToken = createUser(client)

    bookTitle = "book" + uuid.uuid4().hex[:6]
    client.post("/books/v1", json={"book_title": bookTitle, "secret": "ALICE-SECRET"}, headers=authHeader(aliceToken))

    # bob asks for alice's book
    response = client.get("/books/v1/" + bookTitle, headers=authHeader(bobToken))
    assert "ALICE-SECRET" not in response.get_data(as_text=True), "BOLA: bob could read alice's secret"


def testRegisterCannotMakeYourselfAdmin(client):
    userName, token = createUser(client, admin=True)

    response = client.get("/me", headers=authHeader(token))
    isAdmin = response.get_json()["data"]["admin"]
    assert isAdmin is False, "Mass assignment: new user became admin"


def testUserCannotChangeAnotherUsersPassword(client):
    aliceName, aliceToken = createUser(client)
    bobName, bobToken = createUser(client)

    # bob tries to set alice's password
    client.put("/users/v1/" + aliceName + "/password", json={"password": "hacked"}, headers=authHeader(bobToken))

    # alice's password must not be "hacked"
    assert login(client, aliceName, "hacked") is None, "Bob changed alice's password"


def testLoginErrorDoesNotRevealIfUsernameExists(client):
    unknownUser = "nobody" + uuid.uuid4().hex
    realUser, realToken = createUser(client)

    unknownResponse = client.post("/users/v1/login", json={"username": unknownUser, "password": "x"})
    wrongPassResponse = client.post("/users/v1/login", json={"username": realUser, "password": "wrong"})

    # both cases should give the exact same message
    assert unknownResponse.get_data() == wrongPassResponse.get_data(), "Login error leaks which usernames exist"
