"""
Unit tests for ChatDO and /ws/chat/:id routing.
"""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock

from tests.helpers import load_worker, make_env, MockDB, make_stmt, MockRequest

worker = load_worker()
ChatDO = worker.ChatDO


def _make_ctx(sockets: list | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.getWebSockets.return_value = sockets or []
    ctx.setWebSocketAutoResponse.return_value = None
    ctx.acceptWebSocket.return_value = None
    return ctx


def _make_chat_env(*, allow_anon: str = "true", jwt_secret: str = "test-jwt-secret", enc_key: str = "") -> MagicMock:
    env = make_env(jwt_secret=jwt_secret)
    env.ALLOW_ANON_CLASSROOM_POC = allow_anon
    if enc_key:
        env.CHAT_ENCRYPTION_KEY = enc_key
    return env


def _make_request(path: str = "ws://localhost/ws/chat/room1",
                  upgrade: str = "websocket",
                  token: str | None = None,
                  user_id: str | None = None,
                  display_name: str | None = None,
                  classroom_id: str = "room1") -> MockRequest:
    qs_parts = []
    if token:
        qs_parts.append(f"token={token}")
    if user_id:
        qs_parts.append(f"user_id={user_id}")
    if display_name:
        qs_parts.append(f"display_name={display_name}")
    if classroom_id:
        qs_parts.append(f"classroom_id={classroom_id}")
    qs = "&".join(qs_parts)
    url = f"{path}{'?' + qs if qs else ''}"
    headers = {}
    if upgrade:
        headers["Upgrade"] = upgrade
    return MockRequest(method="GET", url=url, headers=headers)


@pytest.mark.asyncio
class TestChatDOFetch:
    async def test_rejects_non_websocket_upgrade(self):
        ctx = _make_ctx()
        env = _make_chat_env()
        do = ChatDO(ctx, env)
        req = MockRequest(method="GET", url="http://localhost/ws/chat/room1")
        resp = await do.on_fetch(req)
        assert resp.status == 426

    async def test_accepts_valid_chat_ws_connection(self):
        ctx = _make_ctx()
        env = _make_chat_env()
        do = ChatDO(ctx, env)
        req = _make_request(user_id="user1", display_name="User One")
        resp = await do.on_fetch(req)
        assert resp.status == 101
        assert len(do.sessions) == 1

    async def test_rejects_anon_when_disabled(self):
        ctx = _make_ctx()
        env = _make_chat_env(allow_anon="false")
        do = ChatDO(ctx, env)
        req = _make_request(user_id="user1", display_name="User One")
        resp = await do.on_fetch(req)
        assert resp.status == 401

    async def test_authenticated_jwt_token_overrides_query_params(self):
        ctx = _make_ctx()
        env = _make_chat_env(jwt_secret="test-jwt-secret")
        token = worker.create_token("uid-verified", "verified_user", "member", "test-jwt-secret")
        do = ChatDO(ctx, env)
        req = _make_request(token=token, user_id="imposter", display_name="Imposter")
        resp = await do.on_fetch(req)
        assert resp.status == 101
        sid = next(iter(do.sessions))
        assert do.sessions[sid]["user_id"] == "uid-verified"
        assert do.sessions[sid]["display_name"] == "verified_user"

    async def test_hibernation_restores_sessions(self):
        mock_ws = MagicMock()
        mock_ws.deserializeAttachment.return_value = json.dumps({
            "session_id": "restored-sess-1",
            "user_id": "alice",
            "display_name": "Alice",
            "classroom_id": "room1",
        })
        ctx = _make_ctx(sockets=[mock_ws])
        env = _make_chat_env()
        do = ChatDO(ctx, env)
        assert "restored-sess-1" in do.sessions
        assert do.sessions["restored-sess-1"]["user_id"] == "alice"
        assert do.sessions["restored-sess-1"]["display_name"] == "Alice"

    async def test_loads_and_sends_chat_history(self):
        ctx = _make_ctx()
        env = _make_chat_env()
        rows = [
            {"id": "msg-1", "user_id": "u1", "display_name": "U1", "content": "Hello", "created_at": "2026-01-01T00:00:00Z"}
        ]
        mock_stmt = make_stmt(all_results=rows)
        env.DB = MockDB([mock_stmt])
        do = ChatDO(ctx, env)
        req = _make_request(user_id="u1", display_name="U1")
        resp = await do.on_fetch(req)
        assert resp.status == 101
        assert len(do.messages) == 1
        assert do.messages[0]["text"] == "Hello"
        sid = next(iter(do.sessions))
        ws = do.sessions[sid]["ws"]
        history_frame = json.loads(ws.send.call_args[0][0])
        assert history_frame["type"] == "chat_history"
        assert len(history_frame["messages"]) == 1

@pytest.mark.asyncio
class TestChatDOMessage:
    async def test_broadcasts_and_persists_chat_message(self):
        ctx = _make_ctx()
        env = _make_chat_env()
        env.DB = MockDB()
        do = ChatDO(ctx, env)

        req1 = _make_request(user_id="u1", display_name="User1")
        await do.on_fetch(req1)
        req2 = _make_request(user_id="u2", display_name="User2")
        await do.on_fetch(req2)

        sids = list(do.sessions.keys())
        ws1 = do.sessions[sids[0]]["ws"]
        ws2 = do.sessions[sids[1]]["ws"]
        ws1.deserializeAttachment.return_value = json.dumps({
            "session_id": sids[0], "user_id": "u1", "display_name": "User1", "classroom_id": "room1"
        })

        msg_payload = json.dumps({"type": "chat_message", "text": "Hello world!"})
        await do.on_webSocketMessage(ws1, msg_payload)

        assert len(do.messages) == 1
        assert do.messages[0]["text"] == "Hello world!"
        broadcast_frame = json.loads(ws2.send.call_args[0][0])
        assert broadcast_frame["type"] == "chat_message"
        assert broadcast_frame["text"] == "Hello world!"
        assert do.messages[0]["text"] == "Hello world!"


@pytest.mark.asyncio
class TestChatDORouting:
    async def test_worker_routes_ws_chat_to_chat_do(self):
        env = make_env()
        mock_stub = MagicMock()
        mock_stub.fetch = AsyncMock(return_value=worker.Response(None, status=101))
        mock_do_ns = MagicMock()
        mock_do_ns.idFromName.return_value = "chat-do-id"
        mock_do_ns.get.return_value = mock_stub
        env.CHAT_DO = mock_do_ns

        req = MockRequest(method="GET", url="http://localhost/ws/chat/room1", headers={"Upgrade": "websocket"})
        resp = await worker.on_fetch(req, env)
        assert resp.status == 101
        mock_do_ns.idFromName.assert_called_with("room1")
