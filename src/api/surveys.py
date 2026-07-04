"""
Survey system — HTTP handlers.

Thin request/response layer over ``surveys.py``: parses auth headers, query
params and JSON bodies, then delegates to the data-access functions and
wraps the result in the project's standard response envelope.
"""

import surveys as core


def _auth_user(req, env):
    return core.verify_token(req.headers.get("Authorization") or "", env.JWT_SECRET)


async def api_list_surveys(req, env):
    user = _auth_user(req, env)
    params = core.get_query_params(req)
    search = (params.get("q") or [""])[0].strip()
    limit = core.query_int(params, "limit", 20, 1, 50)
    offset = core.query_int(params, "offset", 0, 0, 10_000)

    surveys = await core.list_surveys(env, search, limit, offset, user["id"] if user else None)
    return core.json_resp({"surveys": surveys, "limit": limit, "offset": offset})


async def api_create_survey(req, env):
    user = _auth_user(req, env)
    if not user:
        return core.err("Authentication required", 401)

    body, bad_resp = await core.parse_json_object(req)
    if bad_resp:
        return bad_resp

    cleaned, error = core.validate_survey_payload(body)
    if error:
        return core.err(error)

    survey_id = await core.create_survey(env, user["id"], cleaned)
    return core.ok({"id": survey_id, "title": cleaned["title"]}, "Survey created")


async def api_get_survey(survey_id, req, env):
    user = _auth_user(req, env)
    survey = await core.get_survey(env, survey_id, user["id"] if user else None)
    if not survey:
        return core.err("Survey not found", 404)
    return core.json_resp({"survey": survey})


async def api_submit_survey_response(survey_id, req, env):
    user = _auth_user(req, env)

    body, bad_resp = await core.parse_json_object(req)
    if bad_resp:
        return bad_resp

    answers = body.get("answers")
    if not isinstance(answers, dict):
        return core.err("answers must be an object mapping question_id to a value")

    response_id, error = await core.submit_response(
        env, survey_id, user["id"] if user else None, answers
    )
    if error:
        if error == "already_submitted":
            return core.err(
                "You have already submitted a response to this survey",
                400,
                code="already_submitted",
            )
        status = 404 if error == "Survey not found" else 400
        return core.err(error, status)

    return core.ok({"response_id": response_id}, "Response submitted")


async def api_get_survey_results(survey_id, req, env):
    user = _auth_user(req, env)
    results, error = await core.get_results(env, survey_id, user["id"] if user else None)
    if error:
        return core.err(error, 404)
    return core.json_resp({"results": results})


async def api_delete_survey(survey_id, req, env):
    user = _auth_user(req, env)
    if not user:
        return core.err("Authentication required", 401)

    success, error = await core.delete_survey(env, survey_id, user["id"])
    if not success:
        status = 404 if error == "Survey not found" else 403
        return core.err(error, status)

    return core.ok(None, "Survey deleted")


async def api_export_survey(survey_id, req, env):
    user = _auth_user(req, env)
    csv_text, error = await core.export_csv(env, survey_id, user["id"] if user else None)
    if error:
        return core.err(error, 404)

    from workers import Response
    return Response(
        csv_text,
        status=200,
        headers={
            "Content-Type": "text/csv",
            "Content-Disposition": f'attachment; filename="survey-{survey_id}-export.csv"',
            **core.CORS_HEADERS,
        },
    )