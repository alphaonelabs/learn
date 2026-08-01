import base64
import datetime
import json
import os
import re
import uuid
from urllib.parse import urlparse, parse_qs

from workers import Response, DurableObject

import js
from pyodide.ffi import to_js
from js import WebSocketPair, WebSocketRequestResponsePair


# Minimal local helpers to avoid circular imports with worker.py

def _derive_key(secret: str) -> bytes:
    import hashlib
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _decrypt_xor(ciphertext: str, secret: str) -> str:
    if not ciphertext:
        return ""
    try:
        key = _derive_key(secret)
        raw = base64.b64decode(ciphertext)
        ks = (key * (len(raw) // len(key) + 1))[: len(raw)]
        return bytes(a ^ b for a, b in zip(raw, ks)).decode("utf-8")
    except Exception:
        return "[decryption error]"


def _pbkdf2_key(secret: str) -> bytes:
    import hashlib
    salt = hashlib.sha256(b"aol-edu-aes-salt-v1" + secret.encode()).digest()
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100_000)


async def _import_aes_key(key_bytes: bytes) -> object:
    key_buf = to_js(key_bytes, create_pyproxies=False)
    algo = to_js({"name": "AES-GCM"}, dict_converter=js.Object.fromEntries)
    usages = to_js(["encrypt", "decrypt"])
    return await js.crypto.subtle.importKey("raw", key_buf, algo, False, usages)


async def encrypt_aes(plaintext: str, secret: str) -> str:
    if not plaintext:
        return ""
    key_bytes = _pbkdf2_key(secret)
    crypto_key = await _import_aes_key(key_bytes)
    iv_array = js.Uint8Array.new(12)
    js.crypto.getRandomValues(iv_array)
    algo = to_js({"name": "AES-GCM", "iv": iv_array}, dict_converter=js.Object.fromEntries)
    data = to_js(plaintext.encode("utf-8"), create_pyproxies=False)
    ct_buf = await js.crypto.subtle.encrypt(algo, crypto_key, data)
    ct = bytes(js.Uint8Array.new(ct_buf))
    return "v1:" + base64.b64encode(bytes(iv_array) + ct).decode("ascii")


async def decrypt_aes(ciphertext: str, secret: str) -> str:
    if not ciphertext:
        return ""
    if not ciphertext.startswith("v1:"):
        return _decrypt_xor(ciphertext, secret)
    try:
        raw = base64.b64decode(ciphertext[3:])
        iv, ct = raw[:12], raw[12:]
    except Exception:
        return "[decryption error]"
    try:
        key_bytes = _pbkdf2_key(secret)
        crypto_key = await _import_aes_key(key_bytes)
        iv_array = to_js(iv, create_pyproxies=False)
        algo = to_js({"name": "AES-GCM", "iv": iv_array}, dict_converter=js.Object.fromEntries)
        data = to_js(ct, create_pyproxies=False)
        pt_buf = await js.crypto.subtle.decrypt(algo, crypto_key, data)
        return bytes(js.Uint8Array.new(pt_buf)).decode("utf-8")
    except Exception:
        return "[decryption error]"


def new_id() -> str:
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def verify_token(raw: str, secret: str):
    import hashlib, hmac as _hmac
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot = token.rfind(".")
        if dot == -1:
            return None
        p, sig = token[:dot], token[dot + 1 :]
        exp = _hmac.new(secret.encode("utf-8"), p.encode("utf-8"), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, exp):
            return None
        padding = (4 - len(p) % 4) % 4
        return json.loads(base64.b64decode(p + "=" * padding).decode("utf-8"))
    except Exception:
        return None


def _get_field(row, field):
    if hasattr(row, field):
        return getattr(row, field)
    if isinstance(row, dict):
        return row.get(field)
    return None


class ChatDO(DurableObject):
    """Room-scoped real-time chat Durable Object."""

    _MAX_BUFFER = 200

    def __init__(self, ctx, env):
        super().__init__(ctx, env)
        self.sessions = {}
        self.messages = []
        self._history_loaded = False
        self._room_id = getattr(self, "_room_id", "")

        for ws in self.ctx.getWebSockets():
            try:
                attachment = ws.deserializeAttachment()
                if not attachment:
                    continue
                data = json.loads(attachment) if isinstance(attachment, str) else attachment
                session_id = data.get("session_id", str(uuid.uuid4()))
                user_id = str(data.get("user_id", ""))[:64]
                display_name = str(data.get("display_name", user_id or "Unknown"))[:64]
                if not self._room_id:
                    rid = str(data.get("classroom_id", ""))
                    if rid:
                        self._room_id = rid
                if not user_id:
                    continue
                self.sessions[session_id] = {
                    "ws": ws,
                    "user_id": user_id,
                    "display_name": display_name,
                }
            except Exception as exc:
                print(f"[ChatDO.__init__.restore] error={exc!r}")

        self.ctx.setWebSocketAutoResponse(
            WebSocketRequestResponsePair.new("ping", "pong")
        )

    def _session_for_ws(self, ws):
        for s_id, s_info in self.sessions.items():
            try:
                if s_info["ws"] is ws or s_info["ws"] == ws:
                    return s_id, s_info
            except Exception:
                pass
        try:
            raw_att = ws.deserializeAttachment()
            if raw_att:
                att = json.loads(raw_att) if isinstance(raw_att, str) else raw_att
                sid = att.get("session_id")
                info = self.sessions.get(sid)
                if info:
                    return sid, info
        except Exception:
            pass
        return None, None

    async def _load_history(self, classroom_id: str):
        if self._history_loaded:
            return
        try:
            raw_key = getattr(self.env, "CHAT_ENCRYPTION_KEY", None) or getattr(self.env, "ENCRYPTION_KEY", None)
            enc_key = raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else ""
            rows = await self.env.DB.prepare(
                "SELECT id, user_id, display_name, content, created_at FROM chat_message WHERE classroom_id = ? ORDER BY created_at DESC LIMIT ?"
            ).bind(classroom_id, self._MAX_BUFFER).all()
            loaded = []
            for row in (rows.results or []):
                r_content = _get_field(row, "content") or ""
                r_user_id = _get_field(row, "user_id") or ""
                r_display_name = _get_field(row, "display_name") or r_user_id
                r_id = _get_field(row, "id") or ""
                r_created_at = _get_field(row, "created_at") or ""

                text = await decrypt_aes(r_content, enc_key) if (enc_key and r_content) else r_content
                loaded.append({
                    "id": r_id,
                    "user_id": r_user_id,
                    "display_name": r_display_name,
                    "text": text,
                    "timestamp": r_created_at,
                })
            # reverse to chronological order for playback
            self.messages = list(reversed(loaded))
            self._history_loaded = True
        except Exception as exc:
            if "no such table" in str(exc).lower():
                await self._ensure_table()
            else:
                print(f"[ChatDO._load_history] error={exc!r}")

    async def on_fetch(self, request):
        upgrade = request.headers.get("Upgrade") or ""
        if upgrade.lower() != "websocket":
            return Response(json.dumps({"error": "Expected WebSocket upgrade"}), status=426, headers={"Content-Type": "application/json"})

        parsed = urlparse(request.url)
        qs = parse_qs(parsed.query)
        token_param = (qs.get("token") or [None])[0]
        user_param = (qs.get("user_id") or [None])[0]
        display_param = (qs.get("display_name") or [None])[0]
        # Derive classroom_id from path segment /ws/chat/:id
        m = re.fullmatch(r"/ws/chat/([A-Za-z0-9_-]+)", parsed.path or "")
        classroom_id = m.group(1) if m else ""
        if not classroom_id:
            return Response(json.dumps({"error": "Invalid classroom_id"}), status=400, headers={"Content-Type": "application/json"})

        authenticated_user = verify_token(token_param or "", self.env.JWT_SECRET) if token_param else None
        if authenticated_user:
            user_id = str(authenticated_user.get("id", ""))
            display_name = str(authenticated_user.get("username") or user_id)
        else:
            allow_anon = str(getattr(self.env, "ALLOW_ANON_CLASSROOM_POC", "")).lower() in {"1", "true", "yes"}
            if token_param or not allow_anon or not user_param:
                return Response(json.dumps({"error": "Authentication required"}), status=401, headers={"Content-Type": "application/json"})
            user_id = str(user_param)
            display_name = str(display_param or user_id)

        user_id = user_id[:64]
        display_name = display_name[:64]
        if not user_id:
            return Response(json.dumps({"error": "Invalid user_id"}), status=400, headers={"Content-Type": "application/json"})

        client, server = WebSocketPair.new().object_values()
        self.ctx.acceptWebSocket(server)

        session_id = str(uuid.uuid4())
        # Include classroom_id in server-side attachment to support hibernation resume
        self._room_id = classroom_id
        attachment = json.dumps({
            "session_id": session_id,
            "user_id": user_id,
            "display_name": display_name,
            "classroom_id": classroom_id,
        })
        server.serializeAttachment(attachment)

        self.sessions[session_id] = {
            "ws": server,
            "user_id": user_id,
            "display_name": display_name,
        }

        await self._load_history(classroom_id)
        try:
            server.send(json.dumps({"type": "chat_history", "messages": list(self.messages)}))
        except Exception as exc:
            print(f"[ChatDO.on_fetch.send_history] error={exc!r}")

        return Response(None, status=101, web_socket=client)

    async def on_webSocketMessage(self, ws, message):
        try:
            raw = message if isinstance(message, str) else message.decode("utf-8")
            if len(raw) > 4096:
                return
            data = json.loads(raw)
        except Exception:
            return
        if not isinstance(data, dict):
            return

        sid, info = self._session_for_ws(ws)
        if not info:
            return

        if data.get("type") != "chat_message":
            return

        raw_text = data.get("text", "")
        if not isinstance(raw_text, str):
            return
        text = raw_text.strip()[:500]
        if not text:
            return

        classroom_id = getattr(self, "_room_id", "")
        if not classroom_id:
            try:
                raw_att = ws.deserializeAttachment()
                if raw_att:
                    att = json.loads(raw_att) if isinstance(raw_att, str) else raw_att
                    classroom_id = str(att.get("classroom_id", ""))
                    if classroom_id:
                        self._room_id = classroom_id
            except Exception:
                pass

        if not classroom_id:
            try:
                ws.send(json.dumps({"type": "chat_error", "message": "Invalid classroom_id"}))
            except Exception:
                pass
            return

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg_id = new_id()
        entry = {
            "id": msg_id,
            "user_id": info["user_id"],
            "display_name": info["display_name"],
            "text": text,
            "timestamp": timestamp,
        }
        # Persist first; only broadcast if durable
        ok = await self._persist_message(msg_id, classroom_id, info["user_id"], info["display_name"], text, timestamp)
        if not ok:
            try:
                ws.send(json.dumps({"type": "chat_error", "message": "Failed to persist message"}))
            except Exception:
                pass
            return

        self.messages.append(entry)
        if len(self.messages) > self._MAX_BUFFER:
            self.messages = self.messages[-self._MAX_BUFFER :]

        self._broadcast(json.dumps({
            "type": "chat_message",
            "id": msg_id,
            "user_id": info["user_id"],
            "display_name": info["display_name"],
            "text": text,
            "timestamp": timestamp,
        }))

    async def on_webSocketClose(self, ws, _code, _reason, _was_clean):
        sid, _info = self._session_for_ws(ws)
        if sid:
            self.sessions.pop(sid, None)

    async def on_webSocketError(self, _ws, error):
        print(f"[ChatDO.on_webSocketError] error={error!r}")

    def _broadcast(self, payload, exclude_session_id=None):
        for sid, info in self.sessions.items():
            if sid == exclude_session_id:
                continue
            try:
                info["ws"].send(payload)
            except Exception as exc:
                print(f"[ChatDO._broadcast] sid={sid} user_id={info.get('user_id')} error={exc!r}")

    async def _ensure_table(self):
        try:
            await self.env.DB.prepare(
                """CREATE TABLE IF NOT EXISTS chat_message (
                    id           TEXT PRIMARY KEY,
                    classroom_id TEXT NOT NULL,
                    user_id      TEXT NOT NULL,
                    display_name TEXT,
                    content      TEXT NOT NULL,
                    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
                )"""
            ).run()
            await self.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_message(classroom_id, created_at)").run()
        except Exception as exc:
            print(f"[ChatDO._ensure_table] error={exc!r}")

    async def _persist_message(self, msg_id: str, classroom_id: str, user_id: str, display_name: str, text: str, timestamp: str = "") -> bool:
        try:
            raw_key = getattr(self.env, "CHAT_ENCRYPTION_KEY", None) or getattr(self.env, "ENCRYPTION_KEY", None)
            enc_key = raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else ""
            stored_content = await encrypt_aes(text, enc_key) if enc_key else text
            created_at = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            await self.env.DB.prepare(
                "INSERT INTO chat_message (id, classroom_id, user_id, display_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            ).bind(msg_id, classroom_id, user_id, display_name, stored_content, created_at).run()
            return True
        except Exception as exc:
            if "no such table" in str(exc).lower():
                await self._ensure_table()
                try:
                    created_at = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    await self.env.DB.prepare(
                        "INSERT INTO chat_message (id, classroom_id, user_id, display_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)"
                    ).bind(msg_id, classroom_id, user_id, display_name, stored_content, created_at).run()
                    return True
                except Exception as retry_exc:
                    print(f"[ChatDO._persist_message.retry] error={retry_exc!r}")
            else:
                print(f"[ChatDO._persist_message] error={exc!r}")
            return False

