"""
A4 — Peer connections, peer messaging, and secure messaging API handlers.
"""

import datetime
import importlib.util
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from workers import Response


def _worker():
    if "worker" in sys.modules:
        return sys.modules["worker"]
    worker_path = Path(__file__).with_name("worker.py")
    spec = importlib.util.spec_from_file_location("worker", worker_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["worker"] = mod
    spec.loader.exec_module(mod)
    return mod


_w = _worker()
blind_index = _w.blind_index
decrypt_aes = _w.decrypt_aes
encrypt_aes = _w.encrypt_aes
err = _w.err
new_id = _w.new_id
ok = _w.ok
parse_json_object = _w.parse_json_object
verify_token = _w.verify_token


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


async def _notify(env, user_id: str, type_: str, title: str, message: str,
                  related_id: Optional[str] = None) -> None:
    try:
        await _worker()._create_notification(
            env, user_id, type_, title, message,
            related_id=related_id, category="system",
        )
    except Exception:
        # Best-effort: main actions (connections/messages) must not fail solely
        # because notification delivery had an issue. Errors are already
        # captured and logged inside _create_notification.
        return None


async def _user_brief(env, user_id: str, enc: str) -> Optional[dict]:
    row = await env.DB.prepare(
        "SELECT id, name, username FROM users WHERE id = ?"
    ).bind(user_id).first()
    if not row:
        return None
    return {
        "id":       row.id,
        "name":     await decrypt_aes(row.name or "", enc),
        "username": await decrypt_aes(row.username or "", enc),
    }


async def _find_connection(env, user_a: str, user_b: str):
    return await env.DB.prepare(
        "SELECT id, sender_id, receiver_id, status, created_at, updated_at"
        " FROM peer_connections"
        " WHERE (sender_id = ? AND receiver_id = ?)"
        "    OR (sender_id = ? AND receiver_id = ?)"
    ).bind(user_a, user_b, user_b, user_a).first()


def _connection_peer(conn, current_user_id: str) -> str:
    return conn.receiver_id if conn.sender_id == current_user_id else conn.sender_id


def _format_expires(created_at: str) -> str:
    """7-day expiration countdown matching Django secure inbox display."""
    try:
        raw = created_at.replace("T", " ")
        if raw.endswith("Z"):
            raw = raw[:-1]
        created = datetime.datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        if created.tzinfo is None:
            created = created.replace(tzinfo=datetime.timezone.utc)
        expires = created + datetime.timedelta(days=7)
        now = datetime.datetime.now(datetime.timezone.utc)
        remaining = expires - now
        if remaining.total_seconds() <= 0:
            return "0d 0h 0m"
        days = remaining.days
        hours, rem = divmod(remaining.seconds, 3600)
        minutes, _ = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m"
    except Exception:
        return ""


async def _discover_users(env, current_id: str, query: str, enc: str, limit: int = 20) -> list:
    q = (query or "").strip().lower()
    if len(q) < 1:
        return []
    rows = await env.DB.prepare(
        "SELECT id, name, username FROM users WHERE id != ? ORDER BY created_at DESC LIMIT 200"
    ).bind(current_id).all()
    matches = []
    for row in rows.results or []:
        name = await decrypt_aes(row.name or "", enc)
        username = await decrypt_aes(row.username or "", enc)
        if q in (name or "").lower() or q in (username or "").lower():
            matches.append({"id": row.id, "name": name, "username": username})
            if len(matches) >= limit:
                break
    return matches


async def _serialize_connection(env, conn, current_user_id: str, enc: str) -> dict:
    peer_id = _connection_peer(conn, current_user_id)
    peer = await _user_brief(env, peer_id, enc)
    direction = "sent" if conn.sender_id == current_user_id else "received"
    return {
        "id":         conn.id,
        "status":     conn.status,
        "direction":  direction,
        "created_at": conn.created_at,
        "updated_at": conn.updated_at,
        "peer":       peer,
    }


async def api_list_peers(req, env):
    """GET /api/peers — list connections and optionally discover users (?q=)."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    enc = env.ENCRYPTION_KEY
    uid = user["id"]

    sent_rows = await env.DB.prepare(
        "SELECT id, sender_id, receiver_id, status, created_at, updated_at"
        " FROM peer_connections WHERE sender_id = ? ORDER BY updated_at DESC"
    ).bind(uid).all()
    recv_rows = await env.DB.prepare(
        "SELECT id, sender_id, receiver_id, status, created_at, updated_at"
        " FROM peer_connections WHERE receiver_id = ? ORDER BY updated_at DESC"
    ).bind(uid).all()

    sent = []
    for r in sent_rows.results or []:
        sent.append(await _serialize_connection(env, r, uid, enc))
    received = []
    for r in recv_rows.results or []:
        received.append(await _serialize_connection(env, r, uid, enc))

    parsed = urlparse(req.url)
    params = parse_qs(parsed.query)
    raw_q = (params.get("q") or [""])[0]
    q = raw_q.strip() if isinstance(raw_q, str) else ""
    discover = await _discover_users(env, uid, q, enc) if q else []

    return ok({
        "sent":       sent,
        "received":   received,
        "discover":   discover,
    })


async def api_connect(req, env, target_user_id: str):
    """POST /api/peers/connect/:user_id — send a pending connection request."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    uid = user["id"]
    if target_user_id == uid:
        return err("You cannot connect with yourself", 400)

    target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(target_user_id).first()
    if not target:
        return err("User not found", 404)

    existing = await _find_connection(env, uid, target_user_id)
    if existing:
        return err("Connection request already exists", 409)

    enc = env.ENCRYPTION_KEY
    conn_id = new_id()
    now = _now_utc()
    await env.DB.prepare(
        "INSERT INTO peer_connections (id, sender_id, receiver_id, status, created_at, updated_at)"
        " VALUES (?, ?, ?, 'pending', ?, ?)"
    ).bind(conn_id, uid, target_user_id, now, now).run()

    sender_name = user.get("username") or "Someone"
    brief = await _user_brief(env, uid, enc)
    if brief and brief.get("name"):
        sender_name = brief["name"]

    await _notify(
        env, target_user_id, "info", "New Peer Request",
        f"{sender_name} sent you a connection request.",
        related_id=conn_id,
    )

    return ok({"connection_id": conn_id}, "Connection request sent")


async def api_handle_connection(req, env, connection_id: str, action: str):
    """PATCH /api/peers/:connection_id/:action — accept or reject (receiver only)."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    if action not in ("accept", "reject"):
        return err("Invalid action — use accept or reject", 400)

    conn = await env.DB.prepare(
        "SELECT id, sender_id, receiver_id, status FROM peer_connections WHERE id = ?"
    ).bind(connection_id).first()
    if not conn:
        return err("Connection not found", 404)
    if conn.receiver_id != user["id"]:
        return err("Only the recipient can respond to this request", 403)
    if conn.status != "pending":
        return err("Connection is not pending", 400)

    new_status = "accepted" if action == "accept" else "rejected"
    now = _now_utc()
    await env.DB.batch([
        env.DB.prepare(
            "UPDATE peer_connections SET status = ?, updated_at = ? WHERE id = ?"
        ).bind(new_status, now, connection_id),
    ])

    enc = env.ENCRYPTION_KEY
    receiver_brief = await _user_brief(env, user["id"], enc)
    receiver_name = (receiver_brief or {}).get("name") or user.get("username") or "Someone"

    if action == "accept":
        await _notify(
            env, conn.sender_id, "success", "Connection Accepted",
            f"{receiver_name} accepted your connection request.",
            related_id=connection_id,
        )

    return ok({"status": new_status}, f"Connection {new_status}")


async def api_get_peer_messages(req, env, peer_user_id: str):
    """GET /api/peers/messages/:user_id — thread with an accepted peer."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    uid = user["id"]
    conn = await _find_connection(env, uid, peer_user_id)
    if not conn or conn.status != "accepted":
        return err("You must be connected with this user to view messages", 403)

    enc = env.ENCRYPTION_KEY
    rows = await env.DB.prepare(
        "SELECT id, sender_id, receiver_id, content_enc, is_read, read_at, created_at"
        " FROM peer_messages"
        " WHERE (sender_id = ? AND receiver_id = ?)"
        "    OR (sender_id = ? AND receiver_id = ?)"
        " ORDER BY created_at ASC"
    ).bind(uid, peer_user_id, peer_user_id, uid).all()

    now = _now_utc()
    mark_stmts = []
    messages = []
    for r in rows.results or []:
        if r.receiver_id == uid and not r.is_read:
            mark_stmts.append(
                env.DB.prepare(
                    "UPDATE peer_messages SET is_read = 1, read_at = ? WHERE id = ?"
                ).bind(now, r.id)
            )
        messages.append({
            "id":         r.id,
            "sender_id":  r.sender_id,
            "receiver_id": r.receiver_id,
            "content":    await decrypt_aes(r.content_enc or "", enc),
            "is_read":    bool(r.is_read) if r.receiver_id != uid else True,
            "read_at":    r.read_at if r.receiver_id != uid else (r.read_at or now),
            "created_at": r.created_at,
            "mine":       r.sender_id == uid,
        })

    if mark_stmts:
        await env.DB.batch(mark_stmts)

    peer = await _user_brief(env, peer_user_id, enc)
    return ok({"peer": peer, "messages": messages})


async def api_send_peer_message(req, env, peer_user_id: str):
    """POST /api/peers/messages/:user_id — send a message to an accepted peer."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    raw_content = body.get("content")
    if raw_content is None:
        content = ""
    elif isinstance(raw_content, str):
        content = raw_content.strip()
    else:
        return err("content must be a string", 400)
    if not content:
        return err("content is required", 400)

    uid = user["id"]
    conn = await _find_connection(env, uid, peer_user_id)
    if not conn or conn.status != "accepted":
        return err("You must be connected with this user to send messages", 403)

    enc = env.ENCRYPTION_KEY
    msg_id = new_id()
    now = _now_utc()
    content_enc = await encrypt_aes(content, enc)

    await env.DB.batch([
        env.DB.prepare(
            "INSERT INTO peer_messages"
            " (id, sender_id, receiver_id, content_enc, created_at)"
            " VALUES (?, ?, ?, ?, ?)"
        ).bind(msg_id, uid, peer_user_id, content_enc, now),
        env.DB.prepare(
            "UPDATE peer_connections SET updated_at = ? WHERE id = ?"
        ).bind(now, conn.id),
    ])

    sender_name = user.get("username") or "Someone"
    brief = await _user_brief(env, uid, enc)
    if brief and brief.get("name"):
        sender_name = brief["name"]

    await _notify(
        env, peer_user_id, "info", "New Message",
        f"{sender_name} sent you a message.",
        related_id=msg_id,
    )

    return ok({
        "message_id": msg_id,
        "created_at": now,
    }, "Message sent")


async def _resolve_recipient(env, body: dict, enc: str):
    raw_recipient_id = body.get("recipient_id")
    if raw_recipient_id is None:
        recipient_id = ""
    elif isinstance(raw_recipient_id, str):
        recipient_id = raw_recipient_id.strip()
    else:
        return None

    raw_recipient_username = body.get("recipient_username") or body.get("recipient")
    if raw_recipient_username is None:
        recipient_username = ""
    elif isinstance(raw_recipient_username, str):
        recipient_username = raw_recipient_username.strip()
    else:
        return None

    if recipient_id:
        row = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(recipient_id).first()
        return row.id if row else None

    if recipient_username:
        uhash = blind_index(recipient_username, enc)
        row = await env.DB.prepare(
            "SELECT id FROM users WHERE username_hash = ?"
        ).bind(uhash).first()
        return row.id if row else None

    return None


async def api_secure_inbox(req, env):
    """GET /api/secure/inbox — received secure messages, mark unread as read."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    uid = user["id"]
    enc = env.ENCRYPTION_KEY
    rows = await env.DB.prepare(
        "SELECT id, sender_id, content_enc, is_starred, is_read, read_at, created_at"
        " FROM secure_messages WHERE receiver_id = ? ORDER BY created_at ASC"
    ).bind(uid).all()

    now = _now_utc()
    mark_stmts = []
    messages = []
    for r in rows.results or []:
        if not r.is_read:
            mark_stmts.append(
                env.DB.prepare(
                    "UPDATE secure_messages SET is_read = 1, read_at = ? WHERE id = ?"
                ).bind(now, r.id)
            )
        sender = await _user_brief(env, r.sender_id, enc)
        messages.append({
            "id":          r.id,
            "sender":      sender,
            "content":     await decrypt_aes(r.content_enc or "", enc),
            "is_starred":  bool(r.is_starred),
            "is_read":     True,
            "read_at":     r.read_at or now,
            "created_at":  r.created_at,
            "expires_in":  _format_expires(r.created_at),
        })

    if mark_stmts:
        await env.DB.batch(mark_stmts)

    return ok({"messages": messages, "inbox_count": len(messages)})


async def api_secure_send(req, env):
    """POST /api/secure/send — send a secure message to any user."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    raw_message = body.get("message") or body.get("content")
    if raw_message is None:
        message = ""
    elif isinstance(raw_message, str):
        message = raw_message.strip()
    else:
        return err("message must be a string", 400)
    if not message:
        return err("message is required", 400)

    enc = env.ENCRYPTION_KEY
    recipient_id = await _resolve_recipient(env, body, enc)
    if not recipient_id:
        return err("Recipient not found", 404)
    if recipient_id == user["id"]:
        return err("You cannot send a secure message to yourself", 400)

    msg_id = new_id()
    now = _now_utc()
    content_enc = await encrypt_aes(message, enc)

    await env.DB.prepare(
        "INSERT INTO secure_messages"
        " (id, sender_id, receiver_id, content_enc, created_at)"
        " VALUES (?, ?, ?, ?, ?)"
    ).bind(msg_id, user["id"], recipient_id, content_enc, now).run()

    sender_name = user.get("username") or "Someone"
    brief = await _user_brief(env, user["id"], enc)
    if brief and brief.get("name"):
        sender_name = brief["name"]

    await _notify(
        env, recipient_id, "info", "Secure Message",
        f"{sender_name} sent you a secure message.",
        related_id=msg_id,
    )

    return ok({"message_id": msg_id}, "Message sent")


async def api_secure_download(req, env, message_id: str):
    """GET /api/secure/download/:id — download plaintext; delete unless starred."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    row = await env.DB.prepare(
        "SELECT id, content_enc, is_starred FROM secure_messages"
        " WHERE id = ? AND receiver_id = ?"
    ).bind(message_id, user["id"]).first()
    if not row:
        return err("Message not found", 404)

    enc = env.ENCRYPTION_KEY
    plaintext = await decrypt_aes(row.content_enc or "", enc)

    if not row.is_starred:
        await env.DB.batch([
            env.DB.prepare("DELETE FROM secure_messages WHERE id = ?").bind(message_id),
        ])

    return Response(
        plaintext,
        status=200,
        headers={
            "Content-Type":        "text/plain; charset=utf-8",
            "Content-Disposition": f'attachment; filename="message_{message_id}.txt"',
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
    )


async def api_secure_toggle_star(req, env, message_id: str):
    """POST /api/secure/toggle-star/:id — toggle starred (receiver only)."""
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    row = await env.DB.prepare(
        "SELECT id, is_starred FROM secure_messages WHERE id = ? AND receiver_id = ?"
    ).bind(message_id, user["id"]).first()
    if not row:
        return err("Message not found", 404)

    new_starred = 0 if row.is_starred else 1
    await env.DB.prepare(
        "UPDATE secure_messages SET is_starred = ? WHERE id = ?"
    ).bind(new_starred, message_id).run()

    return ok({"is_starred": bool(new_starred)}, "Star toggled")
