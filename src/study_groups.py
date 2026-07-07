import re
from urllib.parse import urlparse, parse_qs


def _required_text(value):
    if value is None:
        return None
    txt = str(value).strip()
    return txt or None


def _optional_text(value):
    if value is None:
        return ""
    txt = str(value).strip()
    return txt


async def _auth(request, env, helpers):
    user = helpers["verify_token"](request.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return None, helpers["err"]("Authentication required", 401)
    if not isinstance(user, dict):
        return None, helpers["err"]("Authentication required", 401)

    user_id = _required_text(user.get("id"))
    if not user_id:
        return None, helpers["err"]("Authentication required", 401)

    user["id"] = user_id
    return user, None


async def _notify(helpers, env, user_id: str, title: str, message: str, related_id: str = None):
    try:
        await helpers["_create_notification"](
            env,
            user_id,
            "info",
            title,
            message,
            related_id=related_id,
            category="system",
        )
    except Exception:
        return None
    return None


async def _run_batch(env, statements):
    if hasattr(env.DB, "batch"):
        return await env.DB.batch(statements)
    for stmt in statements:
        await stmt.run()
    return None


async def _lookup_user(env, helpers, identifier: str):
    identifier = (identifier or "").strip()
    if not identifier:
        return None

    if "@" in identifier:
        email_hash = helpers["blind_index"](identifier, env.ENCRYPTION_KEY)
        return await env.DB.prepare(
            "SELECT id, username FROM users WHERE email_hash=?"
        ).bind(email_hash).first()

    username_hash = helpers["blind_index"](identifier, env.ENCRYPTION_KEY)
    return await env.DB.prepare(
        "SELECT id, username FROM users WHERE username_hash=?"
    ).bind(username_hash).first()


async def _list_groups(request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    params = parse_qs(urlparse(request.url).query)
    activity_id = _optional_text((params.get("activity_id") or [""])[0])

    sql = (
        "SELECT g.id,g.name,g.description,g.activity_id,g.creator_id,g.max_members,"
        "g.is_private,g.created_at,g.updated_at,"
        "COUNT(m.id) AS member_count,"
        "CASE WHEN EXISTS(SELECT 1 FROM study_group_members sm2"
        "                 WHERE sm2.group_id=g.id AND sm2.user_id=?)"
        "     THEN 1 ELSE 0 END AS is_member,"
        "CASE WHEN g.creator_id=? THEN 1 ELSE 0 END AS is_creator"
        " FROM study_groups g"
        " LEFT JOIN study_group_members m ON m.group_id=g.id"
        " WHERE (g.is_private=0 OR EXISTS(SELECT 1 FROM study_group_members sm"
        "                               WHERE sm.group_id=g.id AND sm.user_id=?))"
    )
    bind_args = [user["id"], user["id"], user["id"]]
    if activity_id:
        sql += " AND g.activity_id=?"
        bind_args.append(activity_id)
    sql += " GROUP BY g.id ORDER BY g.created_at DESC"

    try:
        rows = await env.DB.prepare(sql).bind(*bind_args).all()
    except Exception as exc:
        print(f"[study_groups._list_groups.bind] bind_args={bind_args!r} error={exc}")
        return helpers["err"]("Failed to list study groups", 500)

    groups = []
    for r in rows.results or []:
        groups.append({
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "activity_id": r.activity_id,
            "creator_id": r.creator_id,
            "max_members": r.max_members,
            "is_private": bool(r.is_private),
            "member_count": r.member_count,
            "is_member": bool(r.is_member),
            "is_creator": bool(r.is_creator),
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })

    return helpers["ok"]({"groups": groups})


async def _create_group(request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    body, bad_resp = await helpers["parse_json_object"](request)
    if bad_resp:
        return bad_resp

    name = (body.get("name") or "").strip()
    description = _optional_text(body.get("description"))
    # The client no longer supplies activity_id; this handler is responsible
    # for creating a backing activities row (type='study_group') owned by the
    # group creator.
    max_members = body.get("max_members", 10)
    is_private = body.get("is_private", False)

    if not name:
        return helpers["err"]("name is required")

    try:
        max_members = int(max_members)
    except Exception:
        return helpers["err"]("max_members must be an integer")

    if max_members < 2:
        return helpers["err"]("max_members must be at least 2")

    # Create a backing activity row so every study group is represented in the
    # activities model as type='study_group' with the creator as host.
    activity_id = helpers["new_id"]()
    group_id = helpers["new_id"]()
    member_id = helpers["new_id"]()

    try:
        # 1) Insert the activity itself (minimal required columns; other fields
        # use schema defaults).
        stmt_activity = env.DB.prepare(
            "INSERT INTO activities (id,title,type,host_id) VALUES (?,?,?,?)"
        ).bind(activity_id, name, "study_group", user["id"])

        # 2) Insert the study group linked to that activity.
        stmt_group = env.DB.prepare(
            "INSERT INTO study_groups"
            " (id,name,description,activity_id,creator_id,max_members,is_private)"
            " VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?)"
        ).bind(
            group_id,
            name,
            description,
            activity_id,
            user["id"],
            max_members,
            1 if is_private else 0,
        )

        # 3) Insert creator membership row.
        stmt_member = env.DB.prepare(
            "INSERT INTO study_group_members (id,group_id,user_id,role) VALUES (?,?,?,?)"
        ).bind(member_id, group_id, user["id"], "creator")

        await _run_batch(env, [stmt_activity, stmt_group, stmt_member])
    except Exception as exc:
        print(
            "[study_groups._create_group.bind] "
            f"group_id={group_id!r} name={name!r} description={description!r} "
            f"activity_id={activity_id!r} user_id={user.get('id')!r} "
            f"max_members={max_members!r} is_private={is_private!r} error={exc}"
        )
        return helpers["err"]("Failed to create study group", 500)

    row = await env.DB.prepare(
        "SELECT g.id,g.name,g.description,g.activity_id,g.creator_id,g.max_members,"
        "g.is_private,g.created_at,g.updated_at,"
        "(SELECT COUNT(*) FROM study_group_members sm WHERE sm.group_id=g.id) AS member_count"
        " FROM study_groups g WHERE g.id=?"
    ).bind(group_id).first()

    return helpers["ok"]({
        "group": {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "activity_id": row.activity_id,
            "creator_id": row.creator_id,
            "max_members": row.max_members,
            "is_private": bool(row.is_private),
            "member_count": row.member_count,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
    }, "Study group created")


async def _group_detail(group_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    group = await env.DB.prepare(
        "SELECT g.id,g.name,g.description,g.activity_id,g.creator_id,g.max_members,"
        "g.is_private,g.created_at,g.updated_at,u.username AS creator_username_enc"
        " FROM study_groups g"
        " JOIN users u ON u.id=g.creator_id"
        " WHERE g.id=?"
    ).bind(group_id).first()

    if not group:
        return helpers["err"]("Study group not found", 404)

    membership = await env.DB.prepare(
        "SELECT role FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, user["id"]).first()

    if group.is_private and not membership:
        return helpers["err"]("Forbidden", 403)

    rows = await env.DB.prepare(
        "SELECT sm.user_id,sm.role,sm.joined_at,u.username AS username_enc"
        " FROM study_group_members sm"
        " JOIN users u ON u.id=sm.user_id"
        " WHERE sm.group_id=?"
        " ORDER BY sm.joined_at ASC"
    ).bind(group_id).all()

    members = []
    for r in rows.results or []:
        members.append({
            "user_id": r.user_id,
            "username": await helpers["decrypt_aes"](r.username_enc or "", env.ENCRYPTION_KEY),
            "role": r.role,
            "joined_at": r.joined_at,
        })

    creator_username = await helpers["decrypt_aes"](group.creator_username_enc or "", env.ENCRYPTION_KEY)

    return helpers["ok"]({
        "group": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "activity_id": group.activity_id,
            "creator_id": group.creator_id,
            "creator_username": creator_username,
            "max_members": group.max_members,
            "is_private": bool(group.is_private),
            "created_at": group.created_at,
            "updated_at": group.updated_at,
            "member_count": len(members),
            "members": members,
            "requester_role": membership.role if membership else None,
        }
    })


async def _delete_group(group_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    # Fetch creator and backing activity so we can clean up both records.
    row = await env.DB.prepare(
        "SELECT creator_id,activity_id FROM study_groups WHERE id=?"
    ).bind(group_id).first()
    if not row:
        return helpers["err"]("Study group not found", 404)

    if row.creator_id != user["id"]:
        return helpers["err"]("Only the group creator can delete this group", 403)

    statements = []
    if getattr(row, "activity_id", None):
        statements.append(
            env.DB.prepare("DELETE FROM activities WHERE id=?").bind(row.activity_id)
        )

    # Then delete the study group itself.
    statements.append(
        env.DB.prepare("DELETE FROM study_groups WHERE id=?").bind(group_id)
    )

    await _run_batch(env, statements)
    return helpers["ok"](None, "Study group deleted")


async def _join_group(group_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    group = await env.DB.prepare(
        "SELECT id,name,creator_id,max_members,is_private FROM study_groups WHERE id=?"
    ).bind(group_id).first()
    if not group:
        return helpers["err"]("Study group not found", 404)

    if group.is_private:
        return helpers["err"]("Private groups require an invitation", 403)

    existing = await env.DB.prepare(
        "SELECT id FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, user["id"]).first()
    if existing:
        return helpers["err"]("You are already a member of this group", 409)

    count_row = await env.DB.prepare(
        "SELECT COUNT(*) AS cnt FROM study_group_members WHERE group_id=?"
    ).bind(group_id).first()
    if (count_row.cnt if count_row else 0) >= group.max_members:
        return helpers["err"]("This group is full", 400)

    await env.DB.prepare(
        "INSERT INTO study_group_members (id,group_id,user_id,role) VALUES (?,?,?,?)"
    ).bind(helpers["new_id"](), group_id, user["id"], "member").run()

    if group.creator_id != user["id"]:
        await _notify(
            helpers,
            env,
            group.creator_id,
            "New Study Group Member",
            f"{user.get('username', 'A user')} joined {group.name}",
            related_id=group_id,
        )

    return helpers["ok"](None, "Joined study group")


async def _leave_group(group_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    group = await env.DB.prepare(
        "SELECT id,creator_id FROM study_groups WHERE id=?"
    ).bind(group_id).first()
    if not group:
        return helpers["err"]("Study group not found", 404)

    membership = await env.DB.prepare(
        "SELECT id FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, user["id"]).first()
    if not membership:
        return helpers["err"]("You are not a member of this group", 400)

    if group.creator_id == user["id"]:
        return helpers["err"]("Group creator cannot leave the group", 400)

    await env.DB.prepare(
        "DELETE FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, user["id"]).run()

    return helpers["ok"](None, "Left study group")


async def _invite_member(group_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    group = await env.DB.prepare(
        "SELECT id,name FROM study_groups WHERE id=?"
    ).bind(group_id).first()
    if not group:
        return helpers["err"]("Study group not found", 404)

    inviter_membership = await env.DB.prepare(
        "SELECT id FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, user["id"]).first()
    if not inviter_membership:
        return helpers["err"]("Only group members can send invitations", 403)

    body, bad_resp = await helpers["parse_json_object"](request)
    if bad_resp:
        return bad_resp

    invitee_id = (body.get("invitee_id") or "").strip()
    identifier = (body.get("username") or body.get("email_or_username") or "").strip()

    invitee = None
    if invitee_id:
        invitee = await env.DB.prepare("SELECT id, username FROM users WHERE id=?").bind(invitee_id).first()
    elif identifier:
        invitee = await _lookup_user(env, helpers, identifier)

    if not invitee:
        return helpers["err"]("Invitee not found", 404)

    if invitee.id == user["id"]:
        return helpers["err"]("You cannot invite yourself", 400)

    already_member = await env.DB.prepare(
        "SELECT id FROM study_group_members WHERE group_id=? AND user_id=?"
    ).bind(group_id, invitee.id).first()
    if already_member:
        return helpers["err"]("User is already a member of this group", 400)

    pending = await env.DB.prepare(
        "SELECT id FROM study_group_invites"
        " WHERE group_id=? AND invitee_id=? AND status='pending'"
    ).bind(group_id, invitee.id).first()
    if pending:
        return helpers["err"]("A pending invite already exists for this user", 400)

    try:
        await env.DB.prepare(
            "INSERT INTO study_group_invites (id,group_id,inviter_id,invitee_id,status)"
            " VALUES (?,?,?,?,?)"
        ).bind(helpers["new_id"](), group_id, user["id"], invitee.id, "pending").run()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            try:
                await env.DB.prepare(
                    "UPDATE study_group_invites"
                    " SET inviter_id=?, status='pending', updated_at=datetime('now')"
                    " WHERE group_id=? AND invitee_id=?"
                ).bind(user["id"], group_id, invitee.id).run()
            except Exception:
                return helpers["err"]("Failed to create invitation", 500)
            return helpers["ok"](None, "Invitation sent")
        return helpers["err"]("Failed to create invitation", 500)

    await _notify(
        helpers,
        env,
        invitee.id,
        "Study Group Invitation",
        f"{user.get('username', 'A user')} invited you to join {group.name}",
        related_id=group_id,
    )

    return helpers["ok"](None, "Invitation sent")


async def _list_invitations(request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    rows = await env.DB.prepare(
        "SELECT i.id,i.group_id,i.inviter_id,i.status,i.created_at,g.name AS group_name,"
        "u.username AS inviter_username_enc"
        " FROM study_group_invites i"
        " JOIN study_groups g ON g.id=i.group_id"
        " JOIN users u ON u.id=i.inviter_id"
        " WHERE i.invitee_id=? AND i.status='pending'"
        " ORDER BY i.created_at DESC"
    ).bind(user["id"]).all()

    invitations = []
    for r in rows.results or []:
        invitations.append({
            "id": r.id,
            "group_id": r.group_id,
            "group_name": r.group_name,
            "inviter_id": r.inviter_id,
            "inviter_username": await helpers["decrypt_aes"](r.inviter_username_enc or "", env.ENCRYPTION_KEY),
            "status": r.status,
            "created_at": r.created_at,
        })

    return helpers["ok"]({"invitations": invitations})


async def _respond_invitation(invite_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    body, bad_resp = await helpers["parse_json_object"](request)
    if bad_resp:
        return bad_resp

    action = (body.get("action") or "").strip().lower()
    if action not in ("accept", "decline"):
        return helpers["err"]("action must be 'accept' or 'decline'", 400)

    invite = await env.DB.prepare(
        "SELECT i.id,i.group_id,i.inviter_id,i.invitee_id,i.status,g.name AS group_name,g.max_members"
        " FROM study_group_invites i"
        " JOIN study_groups g ON g.id=i.group_id"
        " WHERE i.id=?"
    ).bind(invite_id).first()

    if not invite:
        return helpers["err"]("Invitation not found", 404)

    if invite.invitee_id != user["id"]:
        return helpers["err"]("Only the invitee can respond to this invitation", 403)

    if invite.status != "pending":
        return helpers["err"]("Invitation has already been responded to", 400)

    if action == "accept":
        existing = await env.DB.prepare(
            "SELECT id FROM study_group_members WHERE group_id=? AND user_id=?"
        ).bind(invite.group_id, user["id"]).first()
        if existing:
            return helpers["err"]("You are already a member of this group", 400)

        count_row = await env.DB.prepare(
            "SELECT COUNT(*) AS cnt FROM study_group_members WHERE group_id=?"
        ).bind(invite.group_id).first()

        if (count_row.cnt if count_row else 0) >= invite.max_members:
            return helpers["err"]("This group is full", 400)

        stmt_member = env.DB.prepare(
            "INSERT INTO study_group_members (id,group_id,user_id,role) VALUES (?,?,?,?)"
        ).bind(helpers["new_id"](), invite.group_id, user["id"], "member")

        stmt_update = env.DB.prepare(
            "UPDATE study_group_invites SET status='accepted', updated_at=datetime('now') WHERE id=?"
        ).bind(invite_id)

        try:
            await _run_batch(env, [stmt_member, stmt_update])
        except Exception as exc:
            if "UNIQUE" in str(exc):
                return helpers["err"]("You are already a member of this group", 400)
            return helpers["err"]("Failed to accept invitation", 500)

        await _notify(
            helpers,
            env,
            invite.inviter_id,
            "Invitation Accepted",
            f"{user.get('username', 'A user')} accepted your invite to {invite.group_name}",
            related_id=invite.group_id,
        )
        return helpers["ok"](None, "Invitation accepted")

    await env.DB.prepare(
        "UPDATE study_group_invites SET status='declined', updated_at=datetime('now') WHERE id=?"
    ).bind(invite_id).run()

    await _notify(
        helpers,
        env,
        invite.inviter_id,
        "Invitation Declined",
        f"{user.get('username', 'A user')} declined your invite to {invite.group_name}",
        related_id=invite.group_id,
    )

    return helpers["ok"](None, "Invitation declined")


async def _activity_groups(activity_id: str, request, env, helpers):
    user, bad = await _auth(request, env, helpers)
    if bad:
        return bad

    _ = user
    rows = await env.DB.prepare(
        "SELECT g.id,g.name,g.description,g.activity_id,g.creator_id,g.max_members,"
        "g.is_private,g.created_at,g.updated_at,COUNT(m.id) AS member_count"
        " FROM study_groups g"
        " LEFT JOIN study_group_members m ON m.group_id=g.id"
        " WHERE g.activity_id=? AND g.is_private=0"
        " GROUP BY g.id"
        " ORDER BY g.created_at DESC"
    ).bind(activity_id).all()

    groups = []
    for r in rows.results or []:
        groups.append({
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "activity_id": r.activity_id,
            "creator_id": r.creator_id,
            "max_members": r.max_members,
            "is_private": bool(r.is_private),
            "member_count": r.member_count,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })

    return helpers["ok"]({"groups": groups})


async def handle(request, env, path: str, method: str, helpers):
    if path == "/api/study-groups" and method == "GET":
        return await _list_groups(request, env, helpers)

    if path == "/api/study-groups" and method == "POST":
        return await _create_group(request, env, helpers)

    m_detail = re.fullmatch(r"/api/study-groups/([A-Za-z0-9_-]+)", path)
    if m_detail and method == "GET":
        return await _group_detail(m_detail.group(1), request, env, helpers)
    if m_detail and method == "DELETE":
        return await _delete_group(m_detail.group(1), request, env, helpers)

    m_join = re.fullmatch(r"/api/study-groups/([A-Za-z0-9_-]+)/join", path)
    if m_join and method == "POST":
        return await _join_group(m_join.group(1), request, env, helpers)

    m_leave = re.fullmatch(r"/api/study-groups/([A-Za-z0-9_-]+)/leave", path)
    if m_leave and method == "DELETE":
        return await _leave_group(m_leave.group(1), request, env, helpers)

    m_invite = re.fullmatch(r"/api/study-groups/([A-Za-z0-9_-]+)/invite", path)
    if m_invite and method == "POST":
        return await _invite_member(m_invite.group(1), request, env, helpers)

    if path == "/api/invitations" and method == "GET":
        return await _list_invitations(request, env, helpers)

    m_respond = re.fullmatch(r"/api/invitations/([A-Za-z0-9_-]+)/respond", path)
    if m_respond and method == "POST":
        return await _respond_invitation(m_respond.group(1), request, env, helpers)

    m_activity = re.fullmatch(r"/api/activities/([A-Za-z0-9_-]+)/groups", path)
    if m_activity and method == "GET":
        return await _activity_groups(m_activity.group(1), request, env, helpers)

    return helpers["err"]("API endpoint not found", 404)
