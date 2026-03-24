"""
Activity, enrollment, dashboard, session, and tag API handlers live here.
"""

from urllib.parse import parse_qs, urlparse

from http_utils import capture_exception, err, json_resp, ok, parse_json_object
from security_utils import decrypt, encrypt, new_id, verify_token


async def api_list_activities(req, env):
    parsed = urlparse(req.url)
    params = parse_qs(parsed.query)
    atype  = (params.get("type")   or [None])[0]
    fmt    = (params.get("format") or [None])[0]
    search = (params.get("q")      or [None])[0]
    tag    = (params.get("tag")    or [None])[0]
    enc    = env.ENCRYPTION_KEY

    base_q = (
        "SELECT a.id,a.title,a.description,a.type,a.format,a.schedule_type,"
        "a.created_at,u.name AS host_name_enc,"
        "(SELECT COUNT(*) FROM enrollments WHERE activity_id=a.id AND status='active')"
        " AS participant_count,"
        "(SELECT COUNT(*) FROM sessions WHERE activity_id=a.id) AS session_count"
        " FROM activities a JOIN users u ON a.host_id=u.id"
    )

    if tag:
        tag_row = await env.DB.prepare(
            "SELECT id FROM tags WHERE name=?"
        ).bind(tag).first()
        if not tag_row:
            return json_resp({"activities": []})
        res = await env.DB.prepare(
            base_q
            + " JOIN activity_tags at2 ON at2.activity_id=a.id"
              " WHERE at2.tag_id=? ORDER BY a.created_at DESC"
        ).bind(tag_row.id).all()
    elif atype and fmt:
        res = await env.DB.prepare(
            base_q + " WHERE a.type=? AND a.format=? ORDER BY a.created_at DESC"
        ).bind(atype, fmt).all()
    elif atype:
        res = await env.DB.prepare(
            base_q + " WHERE a.type=? ORDER BY a.created_at DESC"
        ).bind(atype).all()
    elif fmt:
        res = await env.DB.prepare(
            base_q + " WHERE a.format=? ORDER BY a.created_at DESC"
        ).bind(fmt).all()
    else:
        res = await env.DB.prepare(
            base_q + " ORDER BY a.created_at DESC"
        ).all()

    activities = []
    for row in res.results or []:
        desc      = decrypt(row.description or "", enc)
        host_name = decrypt(row.host_name_enc or "", enc)
        if search and (
            search.lower() not in row.title.lower()
            and search.lower() not in desc.lower()
        ):
            continue

        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t"
            " JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(row.id).all()

        activities.append({
            "id":                row.id,
            "title":             row.title,
            "description":       desc,
            "type":              row.type,
            "format":            row.format,
            "schedule_type":     row.schedule_type,
            "host_name":         host_name,
            "participant_count": row.participant_count,
            "session_count":     row.session_count,
            "tags":              [t.name for t in (t_res.results or [])],
            "created_at":        row.created_at,
        })

    return json_resp({"activities": activities})


async def api_create_activity(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    title         = (body.get("title")         or "").strip()
    description   = (body.get("description")   or "").strip()
    atype         = (body.get("type")          or "course").strip()
    fmt           = (body.get("format")        or "self_paced").strip()
    schedule_type = (body.get("schedule_type") or "ongoing").strip()

    if not title:
        return err("title is required")
    if atype not in ("course", "meetup", "workshop", "seminar", "other"):
        atype = "course"
    if fmt not in ("live", "self_paced", "hybrid"):
        fmt = "self_paced"
    if schedule_type not in ("one_time", "multi_session", "recurring", "ongoing"):
        schedule_type = "ongoing"

    enc    = env.ENCRYPTION_KEY
    act_id = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO activities "
            "(id,title,description,type,format,schedule_type,host_id)"
            " VALUES (?,?,?,?,?,?,?)"
        ).bind(
            act_id, title,
            encrypt(description, enc) if description else "",
            atype, fmt, schedule_type, user["id"]
        ).run()
    except Exception as e:
        capture_exception(e, req, env, "api_create_activity.insert_activity")
        return err("Failed to create activity — please try again", 500)

    for tag_name in (body.get("tags") or []):
        tag_name = tag_name.strip()
        if not tag_name:
            continue
        t_row = await env.DB.prepare(
            "SELECT id FROM tags WHERE name=?"
        ).bind(tag_name).first()
        if t_row:
            tag_id = t_row.id
        else:
            tag_id = new_id()
            try:
                await env.DB.prepare(
                    "INSERT INTO tags (id,name) VALUES (?,?)"
                ).bind(tag_id, tag_name).run()
            except Exception as e:
                capture_exception(e, req, env, f"api_create_activity.insert_tag: tag_name={tag_name}, tag_id={tag_id}, act_id={act_id}")
                continue
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id) VALUES (?,?)"
            ).bind(act_id, tag_id).run()
        except Exception as e:
            capture_exception(e, req, env, f"api_create_activity.insert_activity_tags: tag_name={tag_name}, tag_id={tag_id}, act_id={act_id}")
            pass

    return ok({"id": act_id, "title": title}, "Activity created")


async def api_get_activity(act_id: str, req, env):
    user    = verify_token(req.headers.get("Authorization") or "", env.JWT_SECRET)
    enc     = env.ENCRYPTION_KEY

    act = await env.DB.prepare(
        "SELECT a.*,u.name AS host_name_enc,u.id AS host_uid"
        " FROM activities a JOIN users u ON a.host_id=u.id"
        " WHERE a.id=?"
    ).bind(act_id).first()
    if not act:
        return err("Activity not found", 404)

    enrollment  = None
    is_enrolled = False
    if user:
        enrollment  = await env.DB.prepare(
            "SELECT id,role,status FROM enrollments"
            " WHERE activity_id=? AND user_id=?"
        ).bind(act_id, user["id"]).first()
        is_enrolled = enrollment is not None

    is_host = bool(user and act.host_uid == user["id"])

    ses_res = await env.DB.prepare(
        "SELECT id,title,description,start_time,end_time,location,created_at"
        " FROM sessions WHERE activity_id=? ORDER BY start_time"
    ).bind(act_id).all()

    sessions = []
    for s in ses_res.results or []:
        sessions.append({
            "id":          s.id,
            "title":       s.title,
            "description": decrypt(s.description or "", enc) if (is_enrolled or is_host) else None,
            "start_time":  s.start_time,
            "end_time":    s.end_time,
            "location":    decrypt(s.location or "", enc) if (is_enrolled or is_host) else None,
        })

    t_res = await env.DB.prepare(
        "SELECT t.name FROM tags t"
        " JOIN activity_tags at2 ON at2.tag_id=t.id"
        " WHERE at2.activity_id=?"
    ).bind(act_id).all()

    count_row = await env.DB.prepare(
        "SELECT COUNT(*) AS cnt FROM enrollments WHERE activity_id=? AND status='active'"
    ).bind(act_id).first()

    return json_resp({
        "activity": {
            "id":                act.id,
            "title":             act.title,
            "description":       decrypt(act.description or "", enc),
            "type":              act.type,
            "format":            act.format,
            "schedule_type":     act.schedule_type,
            "host_name":         decrypt(act.host_name_enc or "", enc),
            "participant_count": count_row.cnt if count_row else 0,
            "tags":              [t.name for t in (t_res.results or [])],
            "created_at":        act.created_at,
        },
        "sessions":    sessions,
        "is_enrolled": is_enrolled,
        "is_host":     is_host,
        "enrollment":  {
            "role":   enrollment.role,
            "status": enrollment.status,
        } if enrollment else None,
    })


async def api_join(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id = body.get("activity_id")
    role   = (body.get("role") or "participant").strip()

    if not act_id:
        return err("activity_id is required")
    if role not in ("participant", "instructor", "organizer"):
        role = "participant"

    act = await env.DB.prepare(
        "SELECT id FROM activities WHERE id=?"
    ).bind(act_id).first()
    if not act:
        return err("Activity not found", 404)

    enr_id = new_id()
    try:
        await env.DB.prepare(
            "INSERT OR IGNORE INTO enrollments (id,activity_id,user_id,role)"
            " VALUES (?,?,?,?)"
        ).bind(enr_id, act_id, user["id"], role).run()
    except Exception as e:
        capture_exception(e, req, env, "api_join.insert_enrollment")
        return err("Failed to join activity — please try again", 500)

    return ok(None, "Joined activity successfully")


async def api_dashboard(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    enc = env.ENCRYPTION_KEY

    res = await env.DB.prepare(
        "SELECT a.id,a.title,a.type,a.format,a.schedule_type,a.created_at,"
        "(SELECT COUNT(*) FROM enrollments WHERE activity_id=a.id AND status='active')"
        " AS participant_count,"
        "(SELECT COUNT(*) FROM sessions WHERE activity_id=a.id) AS session_count"
        " FROM activities a WHERE a.host_id=? ORDER BY a.created_at DESC"
    ).bind(user["id"]).all()

    hosted = []
    for r in res.results or []:
        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(r.id).all()
        hosted.append({
            "id":                r.id,
            "title":             r.title,
            "type":              r.type,
            "format":            r.format,
            "schedule_type":     r.schedule_type,
            "participant_count": r.participant_count,
            "session_count":     r.session_count,
            "tags":              [t.name for t in (t_res.results or [])],
            "created_at":        r.created_at,
        })

    res2 = await env.DB.prepare(
        "SELECT a.id,a.title,a.type,a.format,a.schedule_type,"
        "e.role AS enr_role,e.status AS enr_status,e.created_at AS joined_at,"
        "u.name AS host_name_enc"
        " FROM enrollments e"
        " JOIN activities a ON e.activity_id=a.id"
        " JOIN users u ON a.host_id=u.id"
        " WHERE e.user_id=? ORDER BY e.created_at DESC"
    ).bind(user["id"]).all()

    joined = []
    for r in res2.results or []:
        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(r.id).all()
        joined.append({
            "id":            r.id,
            "title":         r.title,
            "type":          r.type,
            "format":        r.format,
            "schedule_type": r.schedule_type,
            "enr_role":      r.enr_role,
            "enr_status":    r.enr_status,
            "host_name":     decrypt(r.host_name_enc or "", enc),
            "tags":          [t.name for t in (t_res.results or [])],
            "joined_at":     r.joined_at,
        })

    return json_resp({"user": user, "hosted_activities": hosted, "joined_activities": joined})


async def api_create_session(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id      = body.get("activity_id")
    title       = (body.get("title")       or "").strip()
    description = (body.get("description") or "").strip()
    start_time  = (body.get("start_time")  or "").strip()
    end_time    = (body.get("end_time")    or "").strip()
    location    = (body.get("location")    or "").strip()

    if not act_id or not title:
        return err("activity_id and title are required")

    owned = await env.DB.prepare(
        "SELECT id FROM activities WHERE id=? AND host_id=?"
    ).bind(act_id, user["id"]).first()
    if not owned:
        return err("Activity not found or access denied", 404)

    enc = env.ENCRYPTION_KEY
    sid = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO sessions "
            "(id,activity_id,title,description,start_time,end_time,location)"
            " VALUES (?,?,?,?,?,?,?)"
        ).bind(
            sid, act_id, title,
            encrypt(description, enc) if description else "",
            start_time, end_time,
            encrypt(location, enc) if location else "",
        ).run()
    except Exception as e:
        capture_exception(e, req, env, "api_create_session.insert_session")
        return err("Failed to create session — please try again", 500)

    return ok({"id": sid}, "Session created")


async def api_list_tags(_req, env):
    res  = await env.DB.prepare("SELECT id,name FROM tags ORDER BY name").all()
    tags = [{"id": r.id, "name": r.name} for r in (res.results or [])]
    return json_resp({"tags": tags})


async def api_add_activity_tags(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id = body.get("activity_id")
    tags   = body.get("tags") or []

    if not act_id:
        return err("activity_id is required")

    owned = await env.DB.prepare(
        "SELECT id FROM activities WHERE id=? AND host_id=?"
    ).bind(act_id, user["id"]).first()
    if not owned:
        return err("Activity not found or access denied", 404)

    for tag_name in tags:
        tag_name = tag_name.strip()
        if not tag_name:
            continue
        t_row = await env.DB.prepare(
            "SELECT id FROM tags WHERE name=?"
        ).bind(tag_name).first()
        if t_row:
            tag_id = t_row.id
        else:
            tag_id = new_id()
            try:
                await env.DB.prepare(
                    "INSERT INTO tags (id,name) VALUES (?,?)"
                ).bind(tag_id, tag_name).run()
            except Exception as e:
                capture_exception(e, req, env, f"api_add_activity_tags.insert_tag: tag_name={tag_name}, tag_id={tag_id}, act_id={act_id}")
                continue
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id) VALUES (?,?)"
            ).bind(act_id, tag_id).run()
        except Exception as e:
            capture_exception(e, req, env, f"api_add_activity_tags.insert_activity_tags: tag_name={tag_name}, tag_id={tag_id}, act_id={act_id}")
            pass

    return ok(None, "Tags updated")