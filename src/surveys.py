"""
Survey system — core helpers and D1 data-access layer.

This module is intentionally self-contained (it does not import from
``worker``) so that ``worker.py`` can import it without creating a circular
dependency. The handful of low-level helpers duplicated here (``new_id``,
``verify_token``, the response envelope helpers) are exact copies of the
ones in ``worker.py`` — they are pure, stateless functions so the
duplication carries no risk of behavioural drift.

D1 does not enforce ``PRAGMA foreign_keys = ON`` by default, so cascading
deletes are performed explicitly in ``delete_survey`` rather than relying on
the ``ON DELETE CASCADE`` clauses declared in the migration.
"""

import base64
import csv
import hashlib
import hmac as _hmac
import io
import json
import os
from urllib.parse import parse_qs, urlparse

from workers import Response

QUESTION_TYPES = {"multiple_choice", "checkbox", "text", "true_false", "scale"}
OPTION_QUESTION_TYPES = {"multiple_choice", "checkbox"}
MAX_QUESTIONS = 50
MAX_TITLE_LEN = 200

# Separator used to pack multiple selected checkbox options into a single
# ``survey_answers.answer_text`` column.
CHECKBOX_SEP = "␟"


# ---------------------------------------------------------------------------
# Shared low-level helpers (duplicated from worker.py — see module docstring)
# ---------------------------------------------------------------------------

def new_id() -> str:
    """Generate a random UUID v4 using os.urandom."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def verify_token(raw: str, secret: str):
    """Return decoded payload dict or None if invalid/missing."""
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot = token.rfind(".")
        if dot == -1:
            return None
        p, sig = token[:dot], token[dot + 1:]
        exp = _hmac.new(
            secret.encode("utf-8"), p.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(sig, exp):
            return None
        padding = (4 - len(p) % 4) % 4
        return json.loads(base64.b64decode(p + "=" * padding).decode("utf-8"))
    except Exception:
        return None


_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def json_resp(data, status: int = 200):
    return Response(
        json.dumps(data),
        status=status,
        headers={"Content-Type": "application/json", **_CORS},
    )


def ok(data=None, msg: str = "OK"):
    body = {"success": True, "message": msg}
    if data is not None:
        body["data"] = data
    return json_resp(body, 200)


def err(msg: str, status: int = 400):
    return json_resp({"error": msg}, status)


async def parse_json_object(req):
    """Parse request JSON and ensure payload is an object/dict."""
    try:
        text = await req.text()
        body = json.loads(text)
    except Exception:
        return None, err("Invalid JSON body")

    if not isinstance(body, dict):
        return None, err("JSON body must be an object", 400)

    return body, None


def query_int(params: dict, key: str, default: int, min_val: int, max_val: int) -> int:
    raw = (params.get(key) or [None])[0]
    if raw is None:
        return default
    try:
        return max(min_val, min(int(raw), max_val))
    except (ValueError, TypeError):
        return default


def get_query_params(req) -> dict:
    return parse_qs(urlparse(req.url).query)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_survey_payload(body: dict):
    """Validate a create-survey request body.

    Returns ``(cleaned, None)`` on success or ``(None, error_message)``.
    ``cleaned`` is ``{"title", "description", "is_public", "questions"}``
    where each question is
    ``{"text", "type", "required", "options": [str, ...]}``.
    """
    title = (body.get("title") or "").strip()
    if not title:
        return None, "title is required"
    if len(title) > MAX_TITLE_LEN:
        return None, f"title must be {MAX_TITLE_LEN} characters or fewer"

    description = (body.get("description") or "").strip()
    is_public = bool(body.get("is_public", True))

    questions = body.get("questions")
    if not isinstance(questions, list) or len(questions) == 0:
        return None, "at least 1 question is required"
    if len(questions) > MAX_QUESTIONS:
        return None, f"a survey may have at most {MAX_QUESTIONS} questions"

    cleaned_questions = []
    for i, q in enumerate(questions):
        if not isinstance(q, dict):
            return None, f"question {i + 1} is malformed"

        text = (q.get("text") or "").strip()
        if not text:
            return None, f"question {i + 1} is missing text"

        qtype = (q.get("type") or "").strip()
        if qtype not in QUESTION_TYPES:
            return None, f"question {i + 1} has an invalid type"

        required = bool(q.get("required", False))

        options = []
        if qtype in OPTION_QUESTION_TYPES:
            raw_options = q.get("options")
            if not isinstance(raw_options, list):
                raw_options = []
            options = [str(o).strip() for o in raw_options if str(o).strip()]
            if len(options) < 2:
                return None, f"question {i + 1} needs at least 2 options"

        cleaned_questions.append({
            "text": text,
            "type": qtype,
            "required": required,
            "options": options,
        })

    return {
        "title": title,
        "description": description,
        "is_public": is_public,
        "questions": cleaned_questions,
    }, None


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

async def create_survey(env, user_id: str, cleaned: dict) -> str:
    survey_id = new_id()
    await env.DB.prepare(
        "INSERT INTO surveys (id, user_id, title, description, is_public) "
        "VALUES (?, ?, ?, ?, ?)"
    ).bind(
        survey_id, user_id, cleaned["title"], cleaned["description"],
        1 if cleaned["is_public"] else 0,
    ).run()

    for order, q in enumerate(cleaned["questions"]):
        question_id = new_id()
        await env.DB.prepare(
            "INSERT INTO survey_questions "
            "(id, survey_id, question_text, question_type, required, display_order) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(
            question_id, survey_id, q["text"], q["type"],
            1 if q["required"] else 0, order,
        ).run()

        for opt_order, opt_text in enumerate(q["options"]):
            await env.DB.prepare(
                "INSERT INTO survey_options (id, question_id, option_text, display_order) "
                "VALUES (?, ?, ?, ?)"
            ).bind(new_id(), question_id, opt_text, opt_order).run()

    return survey_id


# ---------------------------------------------------------------------------
# List / detail
# ---------------------------------------------------------------------------

async def list_surveys(env, search: str, limit: int, offset: int, viewer_id):
    where = ["(s.is_public = 1"]
    params = []
    if viewer_id:
        where[0] += " OR s.user_id = ?"
        params.append(viewer_id)
    where[0] += ")"

    if search:
        where.append("(s.title LIKE ? OR s.description LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])

    where_sql = " AND ".join(where)
    params.extend([limit, offset])

    res = await env.DB.prepare(
        "SELECT s.id, s.title, s.description, s.is_public, s.user_id, s.created_at, "
        "u.username AS creator_username, "
        "(SELECT COUNT(*) FROM survey_questions WHERE survey_id = s.id) AS question_count, "
        "(SELECT COUNT(*) FROM survey_responses WHERE survey_id = s.id) AS participant_count "
        "FROM surveys s JOIN users u ON s.user_id = u.id "
        f"WHERE {where_sql} "
        "ORDER BY s.created_at DESC LIMIT ? OFFSET ?"
    ).bind(*params).all()

    surveys = []
    for r in res.results or []:
        surveys.append({
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "is_public": bool(r.is_public),
            "question_count": r.question_count,
            "participant_count": r.participant_count,
            "creator_username": r.creator_username,
            "created_at": r.created_at,
            "is_owner": bool(viewer_id and r.user_id == viewer_id),
        })
    return surveys


async def get_survey(env, survey_id: str, viewer_id):
    survey = await env.DB.prepare(
        "SELECT s.id, s.title, s.description, s.is_public, s.user_id, s.created_at, "
        "s.updated_at, u.username AS creator_username "
        "FROM surveys s JOIN users u ON s.user_id = u.id WHERE s.id = ?"
    ).bind(survey_id).first()

    if not survey:
        return None

    is_owner = bool(viewer_id and survey.user_id == viewer_id)
    if not survey.is_public and not is_owner:
        return None

    q_res = await env.DB.prepare(
        "SELECT id, question_text, question_type, required, display_order "
        "FROM survey_questions WHERE survey_id = ? ORDER BY display_order"
    ).bind(survey_id).all()

    o_res = await env.DB.prepare(
        "SELECT o.id, o.question_id, o.option_text, o.display_order "
        "FROM survey_options o JOIN survey_questions q ON o.question_id = q.id "
        "WHERE q.survey_id = ? ORDER BY o.display_order"
    ).bind(survey_id).all()

    options_by_question = {}
    for o in o_res.results or []:
        options_by_question.setdefault(o.question_id, []).append({
            "id": o.id,
            "text": o.option_text,
        })

    questions = []
    for q in q_res.results or []:
        questions.append({
            "id": q.id,
            "text": q.question_text,
            "type": q.question_type,
            "required": bool(q.required),
            "options": options_by_question.get(q.id, []),
        })

    return {
        "id": survey.id,
        "title": survey.title,
        "description": survey.description,
        "is_public": bool(survey.is_public),
        "creator_username": survey.creator_username,
        "created_at": survey.created_at,
        "updated_at": survey.updated_at,
        "is_owner": is_owner,
        "questions": questions,
    }


# ---------------------------------------------------------------------------
# Submit response
# ---------------------------------------------------------------------------

async def submit_response(env, survey_id: str, user_id, answers: dict):
    """Validate and store a survey response.

    ``answers`` maps ``question_id -> value`` where ``value`` is a string for
    text/true_false/scale questions, or a list of strings for checkbox
    questions.

    Returns ``(response_id, None)`` on success or ``(None, error_message)``.
    """
    survey = await env.DB.prepare(
        "SELECT id, is_public, user_id FROM surveys WHERE id = ?"
    ).bind(survey_id).first()
    if not survey:
        return None, "Survey not found"

    q_res = await env.DB.prepare(
        "SELECT id, question_type, required FROM survey_questions "
        "WHERE survey_id = ? ORDER BY display_order"
    ).bind(survey_id).all()
    questions = q_res.results or []
    if not questions:
        return None, "Survey has no questions"

    o_res = await env.DB.prepare(
        "SELECT o.question_id, o.option_text FROM survey_options o "
        "JOIN survey_questions q ON o.question_id = q.id WHERE q.survey_id = ?"
    ).bind(survey_id).all()
    valid_options = {}
    for o in o_res.results or []:
        valid_options.setdefault(o.question_id, set()).add(o.option_text)

    if user_id:
        existing = await env.DB.prepare(
            "SELECT id FROM survey_responses WHERE survey_id = ? AND user_id = ?"
        ).bind(survey_id, user_id).first()
        if existing:
            return None, "You have already submitted a response to this survey"

    cleaned_answers = []  # list of (question_id, answer_text)
    for q in questions:
        raw = answers.get(q.id)

        if q.question_type == "checkbox":
            values = raw if isinstance(raw, list) else ([] if raw is None else [raw])
            values = [str(v).strip() for v in values if str(v).strip()]
            if q.required and not values:
                return None, "All required questions must be answered"
            allowed = valid_options.get(q.id, set())
            for v in values:
                if v not in allowed:
                    return None, "Invalid option selected"
            if values:
                cleaned_answers.append((q.id, CHECKBOX_SEP.join(values)))
            continue

        value = "" if raw is None else str(raw).strip()
        if q.required and not value:
            return None, "All required questions must be answered"
        if not value:
            continue

        if q.question_type == "multiple_choice":
            if value not in valid_options.get(q.id, set()):
                return None, "Invalid option selected"
        elif q.question_type == "true_false":
            if value not in ("true", "false"):
                return None, "Invalid true/false value"
        elif q.question_type == "scale":
            try:
                n = int(value)
            except ValueError:
                return None, "Invalid scale value"
            if n < 1 or n > 5:
                return None, "Scale value must be between 1 and 5"
            value = str(n)

        cleaned_answers.append((q.id, value))

    response_id = new_id()
    await env.DB.prepare(
        "INSERT INTO survey_responses (id, survey_id, user_id) VALUES (?, ?, ?)"
    ).bind(response_id, survey_id, user_id).run()

    for question_id, answer_text in cleaned_answers:
        await env.DB.prepare(
            "INSERT INTO survey_answers (id, response_id, question_id, answer_text) "
            "VALUES (?, ?, ?, ?)"
        ).bind(new_id(), response_id, question_id, answer_text).run()

    return response_id, None


# ---------------------------------------------------------------------------
# Results / analytics
# ---------------------------------------------------------------------------

async def get_results(env, survey_id: str, viewer_id):
    survey = await env.DB.prepare(
        "SELECT id, title, is_public, user_id FROM surveys WHERE id = ?"
    ).bind(survey_id).first()
    if not survey:
        return None, "Survey not found"
    if not survey.is_public and not (viewer_id and survey.user_id == viewer_id):
        return None, "Survey not found"

    q_res = await env.DB.prepare(
        "SELECT id, question_text, question_type, required, display_order "
        "FROM survey_questions WHERE survey_id = ? ORDER BY display_order"
    ).bind(survey_id).all()
    questions = q_res.results or []

    o_res = await env.DB.prepare(
        "SELECT o.question_id, o.option_text, o.display_order FROM survey_options o "
        "JOIN survey_questions q ON o.question_id = q.id "
        "WHERE q.survey_id = ? ORDER BY o.display_order"
    ).bind(survey_id).all()
    options_by_question = {}
    for o in o_res.results or []:
        options_by_question.setdefault(o.question_id, []).append(o.option_text)

    r_res = await env.DB.prepare(
        "SELECT id FROM survey_responses WHERE survey_id = ?"
    ).bind(survey_id).all()
    response_ids = [r.id for r in (r_res.results or [])]
    participant_count = len(response_ids)

    a_res = await env.DB.prepare(
        "SELECT a.response_id, a.question_id, a.answer_text FROM survey_answers a "
        "JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id = ?"
    ).bind(survey_id).all()
    answers = a_res.results or []

    answers_by_question = {}
    answered_by_response = {}
    for a in answers:
        answers_by_question.setdefault(a.question_id, []).append(a)
        answered_by_response.setdefault(a.response_id, set()).add(a.question_id)

    required_ids = {q.id for q in questions if q.required}
    fully_completed = 0
    total_answer_ratio = 0.0
    for rid in response_ids:
        answered = answered_by_response.get(rid, set())
        if required_ids.issubset(answered):
            fully_completed += 1
        if questions:
            total_answer_ratio += len(answered) / len(questions)

    completion_rate = round((fully_completed / participant_count) * 100, 1) if participant_count else 0.0
    avg_answer_ratio = (total_answer_ratio / participant_count) if participant_count else 0.0
    engagement_score = round(completion_rate * 0.7 + avg_answer_ratio * 100 * 0.3, 1)

    question_results = []
    for q in questions:
        q_answers = answers_by_question.get(q.id, [])
        entry = {
            "id": q.id,
            "text": q.question_text,
            "type": q.question_type,
            "required": bool(q.required),
            "response_count": len(q_answers),
        }

        if q.question_type in ("multiple_choice", "checkbox"):
            option_list = options_by_question.get(q.id, [])
            counts = {opt: 0 for opt in option_list}
            total_selections = 0
            for a in q_answers:
                values = a.answer_text.split(CHECKBOX_SEP) if q.question_type == "checkbox" else [a.answer_text]
                for v in values:
                    if v in counts:
                        counts[v] += 1
                        total_selections += 1
            percentages = {
                opt: (round(counts[opt] / total_selections * 100, 1) if total_selections else 0.0)
                for opt in option_list
            }
            entry["options"] = [
                {"text": opt, "count": counts[opt], "percentage": percentages[opt]}
                for opt in option_list
            ]

        elif q.question_type == "true_false":
            yes = sum(1 for a in q_answers if a.answer_text == "true")
            no = sum(1 for a in q_answers if a.answer_text == "false")
            entry["yes_count"] = yes
            entry["no_count"] = no

        elif q.question_type == "scale":
            values = [int(a.answer_text) for a in q_answers if a.answer_text.isdigit()]
            distribution = {str(n): values.count(n) for n in range(1, 6)}
            entry["average"] = round(sum(values) / len(values), 2) if values else 0.0
            entry["min"] = min(values) if values else 0
            entry["max"] = max(values) if values else 0
            entry["distribution"] = distribution

        elif q.question_type == "text":
            entry["responses"] = [a.answer_text for a in q_answers]

        question_results.append(entry)

    return {
        "survey_id": survey.id,
        "title": survey.title,
        "participant_count": participant_count,
        "completion_rate": completion_rate,
        "engagement_score": engagement_score,
        "question_count": len(questions),
        "questions": question_results,
    }, None


# ---------------------------------------------------------------------------
# Delete (explicit cascade — D1 does not enforce FK pragmas by default)
# ---------------------------------------------------------------------------

async def delete_survey(env, survey_id: str, user_id: str):
    survey = await env.DB.prepare(
        "SELECT user_id FROM surveys WHERE id = ?"
    ).bind(survey_id).first()
    if not survey:
        return False, "Survey not found"
    if survey.user_id != user_id:
        return False, "Only the survey creator can delete this survey"

    await env.DB.prepare(
        "DELETE FROM survey_answers WHERE question_id IN "
        "(SELECT id FROM survey_questions WHERE survey_id = ?)"
    ).bind(survey_id).run()

    await env.DB.prepare(
        "DELETE FROM survey_responses WHERE survey_id = ?"
    ).bind(survey_id).run()

    await env.DB.prepare(
        "DELETE FROM survey_options WHERE question_id IN "
        "(SELECT id FROM survey_questions WHERE survey_id = ?)"
    ).bind(survey_id).run()

    await env.DB.prepare(
        "DELETE FROM survey_questions WHERE survey_id = ?"
    ).bind(survey_id).run()

    await env.DB.prepare(
        "DELETE FROM surveys WHERE id = ?"
    ).bind(survey_id).run()

    return True, None


# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------

async def export_csv(env, survey_id: str, viewer_id):
    survey = await env.DB.prepare(
        "SELECT id, title, is_public, user_id FROM surveys WHERE id = ?"
    ).bind(survey_id).first()
    if not survey:
        return None, "Survey not found"
    if not survey.is_public and not (viewer_id and survey.user_id == viewer_id):
        return None, "Survey not found"

    q_res = await env.DB.prepare(
        "SELECT id, question_text FROM survey_questions "
        "WHERE survey_id = ? ORDER BY display_order"
    ).bind(survey_id).all()
    questions = q_res.results or []

    r_res = await env.DB.prepare(
        "SELECT r.id, r.user_id, r.submitted_at, u.username FROM survey_responses r "
        "LEFT JOIN users u ON r.user_id = u.id WHERE r.survey_id = ? ORDER BY r.submitted_at"
    ).bind(survey_id).all()
    responses = r_res.results or []

    a_res = await env.DB.prepare(
        "SELECT a.response_id, a.question_id, a.answer_text FROM survey_answers a "
        "JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id = ?"
    ).bind(survey_id).all()

    answers_by_response = {}
    for a in (a_res.results or []):
        answers_by_response.setdefault(a.response_id, {})[a.question_id] = a.answer_text.replace(CHECKBOX_SEP, "; ")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Response ID", "Participant", "Submitted At"] + [q.question_text for q in questions])
    for r in responses:
        row_answers = answers_by_response.get(r.id, {})
        writer.writerow(
            [r.id, r.username or "Anonymous", r.submitted_at]
            + [row_answers.get(q.id, "") for q in questions]
        )

    return buf.getvalue(), None
