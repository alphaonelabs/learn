"""
Tests for peer connections and secure messaging API endpoints.
"""

import base64
import json

from tests.helpers import MockRequest, MockRow, MockDB, make_env, make_stmt, load_worker

worker = load_worker()
peers = worker._get_peers_module()

JWT = "test-jwt-secret"
ENC = "test-encryption-key"


def _parse(resp):
    return json.loads(resp.body)


def _enc(val: str) -> str:
    iv = b"\x00" * 12
    return "v1:" + base64.b64encode(iv + val.encode("utf-8")).decode("ascii")


def _auth_header(uid="uid-1", username="alice", role="member"):
    token = worker.create_token(uid, username, role, JWT)
    return {"Authorization": f"Bearer {token}"}


class TestPeersApi:
    async def test_list_peers_requires_auth(self):
        env = make_env(jwt_secret=JWT)
        req = MockRequest(method="GET", url="http://localhost/api/peers")
        resp = await peers.api_list_peers(req, env)
        assert resp.status == 401

    async def test_list_peers_empty(self):
        stmt_sent = make_stmt(all_results=[])
        stmt_recv = make_stmt(all_results=[])
        env = make_env(db=MockDB([stmt_sent, stmt_recv]), jwt_secret=JWT)
        req = MockRequest(method="GET", url="http://localhost/api/peers", headers=_auth_header())
        resp = await peers.api_list_peers(req, env)
        body = _parse(resp)
        assert resp.status == 200
        assert body["data"]["sent"] == []
        assert body["data"]["received"] == []

    async def test_connect_rejects_self(self):
        env = make_env(jwt_secret=JWT)
        req = MockRequest(
            method="POST",
            url="http://localhost/api/peers/connect/uid-1",
            headers=_auth_header("uid-1"),
        )
        resp = await peers.api_connect(req, env, "uid-1")
        assert resp.status == 400

    async def test_connect_user_not_found(self):
        stmt = make_stmt(first=None)
        env = make_env(db=MockDB([stmt]), jwt_secret=JWT)
        req = MockRequest(
            method="POST",
            url="http://localhost/api/peers/connect/uid-2",
            headers=_auth_header("uid-1"),
        )
        resp = await peers.api_connect(req, env, "uid-2")
        assert resp.status == 404

    async def test_peer_messages_requires_connection(self):
        stmt = make_stmt(first=None)
        env = make_env(db=MockDB([stmt]), jwt_secret=JWT)
        req = MockRequest(
            method="GET",
            url="http://localhost/api/peers/messages/uid-2",
            headers=_auth_header("uid-1"),
        )
        resp = await peers.api_get_peer_messages(req, env, "uid-2")
        assert resp.status == 403

    async def test_handle_connection_invalid_action(self):
        env = make_env(jwt_secret=JWT)
        req = MockRequest(
            method="PATCH",
            url="http://localhost/api/peers/conn-1/block",
            headers=_auth_header(),
        )
        resp = await peers.api_handle_connection(req, env, "conn-1", "block")
        assert resp.status == 400


class TestSecureMessagingApi:
    async def test_secure_inbox_requires_auth(self):
        env = make_env(jwt_secret=JWT)
        req = MockRequest(method="GET", url="http://localhost/api/secure/inbox")
        resp = await peers.api_secure_inbox(req, env)
        assert resp.status == 401

    async def test_secure_send_missing_message(self):
        env = make_env(jwt_secret=JWT)
        req = MockRequest(
            method="POST",
            url="http://localhost/api/secure/send",
            headers={**_auth_header(), "Content-Type": "application/json"},
            body=json.dumps({"recipient_username": "bob"}),
        )
        resp = await peers.api_secure_send(req, env)
        assert resp.status == 400

    async def test_secure_toggle_star_not_found(self):
        stmt = make_stmt(first=None)
        env = make_env(db=MockDB([stmt]), jwt_secret=JWT)
        req = MockRequest(
            method="POST",
            url="http://localhost/api/secure/toggle-star/msg-1",
            headers=_auth_header(),
        )
        resp = await peers.api_secure_toggle_star(req, env, "msg-1")
        assert resp.status == 404


class TestPeersDispatch:
    async def test_dispatch_peers_route(self):
        stmt_sent = make_stmt(all_results=[])
        stmt_recv = make_stmt(all_results=[])
        env = make_env(db=MockDB([stmt_sent, stmt_recv]), jwt_secret=JWT)
        req = MockRequest(method="GET", url="http://localhost/api/peers", headers=_auth_header())
        resp = await worker.on_fetch(req, env)
        assert resp.status == 200
