"""
Authentication-related API handlers live here.
"""

from http_utils import capture_exception, err, ok, parse_json_object
from security_utils import (
    blind_index,
    create_token,
    decrypt,
    encrypt,
    hash_password,
    new_id,
    verify_password,
)

# ---------------------------------------------------------------------------
# API handlers
# ---------------------------------------------------------------------------

async def api_register(req, env):
    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    username = (body.get("username") or "").strip()
    email    = (body.get("email")    or "").strip()
    password = (body.get("password") or "")
    name     = (body.get("name")     or username).strip()

    if not username or not email or not password:
        return err("username, email, and password are required")
    if len(password) < 8:
        return err("Password must be at least 8 characters")

    role = "member"

    enc = env.ENCRYPTION_KEY
    uid = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO users "
            "(id,username_hash,email_hash,name,username,email,password_hash,role)"
            " VALUES (?,?,?,?,?,?,?,?)"
        ).bind(
            uid,
            blind_index(username, enc),
            blind_index(email,    enc),
            encrypt(name,     enc),
            encrypt(username, enc),
            encrypt(email,    enc),
            hash_password(password, username),
            encrypt(role, enc),
        ).run()
    except Exception as e:
        if "UNIQUE" in str(e):
            return err("Username or email already registered", 409)
        capture_exception(e, req, env, "api_register.insert_user")
        return err("Registration failed — please try again", 500)

    token = create_token(uid, username, role, env.JWT_SECRET)
    return ok(
        {"token": token,
         "user": {"id": uid, "username": username, "name": name, "role": role}},
        "Registration successful",
    )


async def api_login(req, env):
    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    username = (body.get("username") or "").strip()
    password = (body.get("password") or "")

    if not username or not password:
        return err("username and password are required")

    enc    = env.ENCRYPTION_KEY
    u_hash = blind_index(username, enc)
    row    = await env.DB.prepare(
        "SELECT id,password_hash,role,name,username FROM users WHERE username_hash=?"
    ).bind(u_hash).first()

    if not row:
        return err("Invalid username or password", 401)
    
    password_hash = row.password_hash
    user_id = row.id
    role_enc = row.role
    name_enc = row.name
    username_enc = row.username
    stored_username = decrypt(username_enc, enc)

    if not verify_password(password, password_hash, stored_username):
        return err("Invalid username or password", 401)

    real_role = decrypt(role_enc, enc)
    real_name = decrypt(name_enc, enc)
    token     = create_token(user_id, stored_username, real_role, env.JWT_SECRET)
    return ok(
        {"token": token,
         "user": {"id": user_id, "username": stored_username,
                  "name": real_name, "role": real_role}},
        "Login successful",
    )
