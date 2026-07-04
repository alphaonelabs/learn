"""
Tests for the survey system API handlers (src/api/surveys.py, src/surveys.py):
  * api_list_surveys()
  * api_create_survey()
  * api_get_survey()
  * api_submit_survey_response()
  * api_get_survey_results()
  * api_delete_survey()
  * api_export_survey()
"""

import json

from tests.helpers import load_worker, MockRequest, MockRow, MockDB, make_env, make_stmt, json_request

worker = load_worker()

JWT = "test-jwt-secret"


def _parse(resp):
    return json.loads(resp.body)


def _token(uid="user-1", username="alice", role="user"):
    return worker.create_token(uid, username, role, JWT)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _get_req(path, token=None):
    headers = _auth_header(token) if token else {}
    return MockRequest(method="GET", url=f"http://localhost{path}", headers=headers)


def _delete_req(path, token=None):
    headers = _auth_header(token) if token else {}
    return MockRequest(method="DELETE", url=f"http://localhost{path}", headers=headers)


def _basic_survey_payload(qtype="text"):
    return {
        "title": "Customer Feedback",
        "description": "Tell us what you think",
        "is_public": True,
        "questions": [
            {"text": "How was your experience?", "type": qtype, "required": True,
             **({"options": ["Good", "Bad"]} if qtype in ("multiple_choice", "checkbox") else {})},
        ],
    }


# ---------------------------------------------------------------------------
# Local helper: MockDB variant that supports D1's batch() API.
#
# ``delete_survey()`` in src/surveys.py issues its cascading deletes via
# ``env.DB.batch([...])`` (a real method on Cloudflare's D1 binding) so the
# whole cascade commits atomically. The shared ``MockDB`` in tests/helpers.py
# intentionally only stubs the primitives the rest of the suite relies on
# (``prepare``/``bind``/``run``/``first``/``all``), so rather than widen that
# shared double for every test in the project, we extend it locally here,
# scoped to just the survey-deletion test that needs it.
# ---------------------------------------------------------------------------

class BatchMockDB(MockDB):
    async def batch(self, statements):
        results = []
        for stmt in statements:
            results.append(await stmt.run())
        return results


# ---------------------------------------------------------------------------
# api_create_survey()
# ---------------------------------------------------------------------------

class TestApiCreateSurvey:
    def _req(self, payload, token=None):
        headers = _auth_header(token) if token else {}
        return json_request("/api/surveys", payload, headers=headers)

    async def test_no_auth_returns_401(self):
        env = make_env()
        r = await worker.api_create_survey(self._req(_basic_survey_payload()), env)
        assert r.status == 401

    async def test_missing_title_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["title"] = "   "
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400
        assert "title" in _parse(r)["error"]

    async def test_title_too_long_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["title"] = "x" * 201
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400

    async def test_no_questions_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["questions"] = []
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400
        assert "question" in _parse(r)["error"]

    async def test_too_many_questions_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["questions"] = [{"text": f"Q{i}", "type": "text"} for i in range(51)]
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400

    async def test_invalid_question_type_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["questions"][0]["type"] = "essay"
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400

    async def test_missing_question_text_returns_400(self):
        token = _token()
        body = _basic_survey_payload()
        body["questions"][0]["text"] = ""
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400

    async def test_multiple_choice_without_enough_options_returns_400(self):
        token = _token()
        body = _basic_survey_payload(qtype="multiple_choice")
        body["questions"][0]["options"] = ["Only One"]
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400
        assert "options" in _parse(r)["error"]

    async def test_checkbox_without_options_returns_400(self):
        token = _token()
        body = _basic_survey_payload(qtype="checkbox")
        body["questions"][0]["options"] = []
        env = make_env()
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 400

    async def test_invalid_json_body_returns_400(self):
        token = _token()
        req = MockRequest(method="POST", url="http://localhost/api/surveys",
                           headers={**_auth_header(token), "Content-Type": "application/json"},
                           body="not json")
        env = make_env()
        r = await worker.api_create_survey(req, env)
        assert r.status == 400

    async def test_successful_creation_text_question(self):
        token = _token()
        env = make_env(db=MockDB())
        r = await worker.api_create_survey(self._req(_basic_survey_payload(), token), env)
        assert r.status == 200
        data = _parse(r)
        assert data["success"] is True
        assert data["data"]["title"] == "Customer Feedback"

    async def test_successful_creation_with_options(self):
        token = _token()
        env = make_env(db=MockDB())
        r = await worker.api_create_survey(
            self._req(_basic_survey_payload(qtype="multiple_choice"), token), env
        )
        assert r.status == 200

    async def test_is_public_defaults_true_when_omitted(self):
        token = _token()
        body = _basic_survey_payload()
        del body["is_public"]
        env = make_env(db=MockDB())
        r = await worker.api_create_survey(self._req(body, token), env)
        assert r.status == 200


# ---------------------------------------------------------------------------
# api_list_surveys()
# ---------------------------------------------------------------------------

class TestApiListSurveys:
    def _row(self, sid="s1", title="Feedback", user_id="user-1", is_public=1):
        return MockRow(
            id=sid, title=title, description="desc", is_public=is_public, user_id=user_id,
            created_at="2024-01-01T00:00:00", creator_username="alice",
            question_count=3, participant_count=10,
        )

    async def test_returns_surveys_list(self):
        env = make_env(db=MockDB([make_stmt(all_results=[self._row()])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys"), env)
        assert r.status == 200
        data = _parse(r)
        assert len(data["surveys"]) == 1
        assert data["surveys"][0]["title"] == "Feedback"

    async def test_empty_list(self):
        env = make_env(db=MockDB([make_stmt(all_results=[])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys"), env)
        assert _parse(r)["surveys"] == []

    async def test_is_owner_true_for_creator(self):
        token = _token(uid="user-1")
        env = make_env(db=MockDB([make_stmt(all_results=[self._row(user_id="user-1")])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys", token), env)
        assert _parse(r)["surveys"][0]["is_owner"] is True

    async def test_is_owner_false_for_anonymous(self):
        env = make_env(db=MockDB([make_stmt(all_results=[self._row(user_id="user-1")])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys"), env)
        assert _parse(r)["surveys"][0]["is_owner"] is False

    async def test_search_query_param_accepted(self):
        env = make_env(db=MockDB([make_stmt(all_results=[])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys?q=feedback"), env)
        assert r.status == 200

    async def test_pagination_params_clamped(self):
        env = make_env(db=MockDB([make_stmt(all_results=[])]))
        r = await worker.api_list_surveys(_get_req("/api/surveys?limit=500&offset=-5"), env)
        data = _parse(r)
        assert data["limit"] == 50


# ---------------------------------------------------------------------------
# api_get_survey()
# ---------------------------------------------------------------------------

class TestApiGetSurvey:
    def _survey_row(self, sid="s1", user_id="user-1", is_public=1):
        return MockRow(
            id=sid, title="Feedback", description="desc", is_public=is_public,
            user_id=user_id, created_at="2024-01-01", updated_at="2024-01-01",
            creator_username="alice",
        )

    def _question_row(self, qid="q1"):
        return MockRow(id=qid, question_text="How was it?", question_type="multiple_choice",
                        required=1, display_order=0)

    def _option_row(self, qid="q1"):
        return MockRow(id="o1", question_id=qid, option_text="Good", display_order=0)

    async def test_not_found_returns_404(self):
        env = make_env(db=MockDB([make_stmt(first=None)]))
        r = await worker.api_get_survey("missing", _get_req("/api/surveys/missing"), env)
        assert r.status == 404

    async def test_public_survey_visible_to_anonymous(self):
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._question_row()]),
            make_stmt(all_results=[self._option_row()]),
        ]))
        r = await worker.api_get_survey("s1", _get_req("/api/surveys/s1"), env)
        assert r.status == 200
        data = _parse(r)["survey"]
        assert data["title"] == "Feedback"
        assert len(data["questions"]) == 1
        assert len(data["questions"][0]["options"]) == 1

    async def test_private_survey_hidden_from_non_owner(self):
        token = _token(uid="someone-else")
        env = make_env(db=MockDB([make_stmt(first=self._survey_row(is_public=0))]))
        r = await worker.api_get_survey("s1", _get_req("/api/surveys/s1", token), env)
        assert r.status == 404

    async def test_private_survey_visible_to_owner(self):
        token = _token(uid="user-1")
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row(is_public=0)),
            make_stmt(all_results=[self._question_row()]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_get_survey("s1", _get_req("/api/surveys/s1", token), env)
        assert r.status == 200
        assert _parse(r)["survey"]["is_owner"] is True


# ---------------------------------------------------------------------------
# api_submit_survey_response()
# ---------------------------------------------------------------------------

class TestApiSubmitSurveyResponse:
    def _req(self, survey_id, answers, token=None):
        headers = _auth_header(token) if token else {}
        return json_request(f"/api/surveys/{survey_id}/responses", {"answers": answers}, headers=headers)

    def _survey_row(self, sid="s1", is_public=1, user_id="user-1"):
        return MockRow(id=sid, is_public=is_public, user_id=user_id)

    def _text_question(self):
        return MockRow(id="q1", question_type="text", required=True)

    def _mc_question(self):
        return MockRow(id="q1", question_type="multiple_choice", required=True)

    def _option_row(self, text="Good"):
        return MockRow(question_id="q1", option_text=text)

    async def test_survey_not_found_returns_404(self):
        env = make_env(db=MockDB([make_stmt(first=None)]))
        r = await worker.api_submit_survey_response("missing", self._req("missing", {"q1": "hi"}), env)
        assert r.status == 404

    async def test_answers_must_be_object(self):
        env = make_env()
        req = json_request("/api/surveys/s1/responses", {"answers": "not-an-object"})
        r = await worker.api_submit_survey_response("s1", req, env)
        assert r.status == 400

    async def test_no_questions_returns_400(self):
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {}), env)
        assert r.status == 400

    async def test_required_question_missing_returns_400(self):
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._text_question()]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {}), env)
        assert r.status == 400
        assert "required" in _parse(r)["error"].lower()

    async def test_invalid_option_returns_400(self):
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._mc_question()]),
            make_stmt(all_results=[self._option_row("Good")]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "Not An Option"}), env)
        assert r.status == 400

    async def test_successful_anonymous_submission(self):
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._text_question()]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "Great!"}), env)
        assert r.status == 200
        assert _parse(r)["data"]["response_id"]

    async def test_successful_authenticated_submission(self):
        token = _token(uid="user-9")
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._text_question()]),
            make_stmt(all_results=[]),
            make_stmt(first=None),  # no existing response
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "Great!"}, token), env)
        assert r.status == 200

    async def test_duplicate_submission_blocked(self):
        token = _token(uid="user-9")
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[self._text_question()]),
            make_stmt(all_results=[]),
            make_stmt(first=MockRow(id="existing-response")),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "Again"}, token), env)
        assert r.status == 400
        assert "already" in _parse(r)["error"].lower()

    async def test_checkbox_multiple_selections_accepted(self):
        q = MockRow(id="q1", question_type="checkbox", required=False)
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[self._option_row("Good"), self._option_row("Bad")]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": ["Good", "Bad"]}), env)
        assert r.status == 200

    async def test_scale_out_of_range_returns_400(self):
        q = MockRow(id="q1", question_type="scale", required=True)
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "9"}), env)
        assert r.status == 400

    async def test_true_false_invalid_value_returns_400(self):
        q = MockRow(id="q1", question_type="true_false", required=True)
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_submit_survey_response("s1", self._req("s1", {"q1": "maybe"}), env)
        assert r.status == 400


# ---------------------------------------------------------------------------
# api_get_survey_results()
# ---------------------------------------------------------------------------

class TestApiGetSurveyResults:
    def _survey_row(self, sid="s1", is_public=1, user_id="user-1"):
        return MockRow(id=sid, title="Feedback", is_public=is_public, user_id=user_id)

    async def test_not_found_returns_404(self):
        env = make_env(db=MockDB([make_stmt(first=None)]))
        r = await worker.api_get_survey_results("missing", _get_req("/api/surveys/missing/results"), env)
        assert r.status == 404

    async def test_private_survey_hidden_from_non_owner(self):
        token = _token(uid="someone-else")
        env = make_env(db=MockDB([make_stmt(first=self._survey_row(is_public=0))]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results", token), env)
        assert r.status == 404

    async def test_multiple_choice_counts_and_percentages(self):
        q = MockRow(id="q1", question_text="Pick", question_type="multiple_choice",
                     required=1, display_order=0)
        opts = [MockRow(question_id="q1", option_text="A", display_order=0),
                MockRow(question_id="q1", option_text="B", display_order=1)]
        responses = [MockRow(id="r1"), MockRow(id="r2")]
        answers = [MockRow(response_id="r1", question_id="q1", answer_text="A"),
                   MockRow(response_id="r2", question_id="q1", answer_text="B")]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=opts),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results"), env)
        assert r.status == 200
        results = _parse(r)["results"]
        assert results["participant_count"] == 2
        assert results["completion_rate"] == 100.0
        opt_a = next(o for o in results["questions"][0]["options"] if o["text"] == "A")
        assert opt_a["count"] == 1
        assert opt_a["percentage"] == 50.0

    async def test_true_false_yes_no_totals(self):
        q = MockRow(id="q1", question_text="Like it?", question_type="true_false",
                     required=0, display_order=0)
        responses = [MockRow(id="r1"), MockRow(id="r2"), MockRow(id="r3")]
        answers = [
            MockRow(response_id="r1", question_id="q1", answer_text="true"),
            MockRow(response_id="r2", question_id="q1", answer_text="true"),
            MockRow(response_id="r3", question_id="q1", answer_text="false"),
        ]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results"), env)
        q_result = _parse(r)["results"]["questions"][0]
        assert q_result["yes_count"] == 2
        assert q_result["no_count"] == 1

    async def test_scale_avg_min_max_distribution(self):
        q = MockRow(id="q1", question_text="Rate us", question_type="scale",
                     required=0, display_order=0)
        responses = [MockRow(id="r1"), MockRow(id="r2"), MockRow(id="r3")]
        answers = [
            MockRow(response_id="r1", question_id="q1", answer_text="3"),
            MockRow(response_id="r2", question_id="q1", answer_text="5"),
            MockRow(response_id="r3", question_id="q1", answer_text="1"),
        ]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results"), env)
        q_result = _parse(r)["results"]["questions"][0]
        assert q_result["average"] == 3.0
        assert q_result["min"] == 1
        assert q_result["max"] == 5
        assert q_result["distribution"]["1"] == 1
        assert q_result["distribution"]["5"] == 1

    async def test_text_responses_listed(self):
        q = MockRow(id="q1", question_text="Comments?", question_type="text",
                     required=0, display_order=0)
        responses = [MockRow(id="r1"), MockRow(id="r2")]
        answers = [
            MockRow(response_id="r1", question_id="q1", answer_text="Great course!"),
            MockRow(response_id="r2", question_id="q1", answer_text="Could be better"),
        ]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results"), env)
        q_result = _parse(r)["results"]["questions"][0]
        assert "Great course!" in q_result["responses"]
        assert len(q_result["responses"]) == 2

    async def test_no_participants_yields_zero_stats(self):
        q = MockRow(id="q1", question_text="Comments?", question_type="text",
                     required=0, display_order=0)
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=[]),
            make_stmt(all_results=[]),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_get_survey_results("s1", _get_req("/api/surveys/s1/results"), env)
        results = _parse(r)["results"]
        assert results["participant_count"] == 0
        assert results["completion_rate"] == 0.0


# ---------------------------------------------------------------------------
# api_delete_survey()
# ---------------------------------------------------------------------------

class TestApiDeleteSurvey:
    async def test_no_auth_returns_401(self):
        env = make_env()
        r = await worker.api_delete_survey("s1", _delete_req("/api/surveys/s1"), env)
        assert r.status == 401

    async def test_not_found_returns_404(self):
        token = _token(uid="user-1")
        env = make_env(db=MockDB([make_stmt(first=None)]))
        r = await worker.api_delete_survey("s1", _delete_req("/api/surveys/s1", token), env)
        assert r.status == 404

    async def test_non_owner_returns_403(self):
        token = _token(uid="someone-else")
        env = make_env(db=MockDB([make_stmt(first=MockRow(user_id="user-1"))]))
        r = await worker.api_delete_survey("s1", _delete_req("/api/surveys/s1", token), env)
        assert r.status == 403

    async def test_owner_can_delete(self):
        token = _token(uid="user-1")
        # delete_survey() runs its cascade via env.DB.batch([...]); use the
        # local batch-aware MockDB subclass so that call has something to hit.
        env = make_env(db=BatchMockDB([make_stmt(first=MockRow(user_id="user-1"))]))
        r = await worker.api_delete_survey("s1", _delete_req("/api/surveys/s1", token), env)
        assert r.status == 200
        assert _parse(r)["success"] is True


# ---------------------------------------------------------------------------
# api_export_survey()
# ---------------------------------------------------------------------------

class TestApiExportSurvey:
    def _survey_row(self, is_public=1, user_id="user-1"):
        return MockRow(id="s1", title="Feedback", is_public=is_public, user_id=user_id)

    async def test_not_found_returns_404(self):
        env = make_env(db=MockDB([make_stmt(first=None)]))
        r = await worker.api_export_survey("missing", _get_req("/api/surveys/missing/export"), env)
        assert r.status == 404

    async def test_private_survey_hidden_from_non_owner(self):
        token = _token(uid="someone-else")
        env = make_env(db=MockDB([make_stmt(first=self._survey_row(is_public=0))]))
        r = await worker.api_export_survey("s1", _get_req("/api/surveys/s1/export", token), env)
        assert r.status == 404

    async def test_returns_csv_content_type(self):
        q = MockRow(id="q1", question_text="Comments?")
        responses = [MockRow(id="r1", user_id="user-9", submitted_at="2024-01-01", username="bob")]
        answers = [MockRow(response_id="r1", question_id="q1", answer_text="Nice!")]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_export_survey("s1", _get_req("/api/surveys/s1/export"), env)
        assert r.status == 200
        assert r.headers["Content-Type"] == "text/csv"

    async def test_csv_contains_header_and_rows(self):
        q = MockRow(id="q1", question_text="Comments?")
        responses = [MockRow(id="r1", user_id="user-9", submitted_at="2024-01-01", username="bob")]
        answers = [MockRow(response_id="r1", question_id="q1", answer_text="Nice!")]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=responses),
            make_stmt(all_results=answers),
        ]))
        r = await worker.api_export_survey("s1", _get_req("/api/surveys/s1/export"), env)
        assert "Comments?" in r.body
        assert "bob" in r.body
        assert "Nice!" in r.body

    async def test_anonymous_response_labeled_in_csv(self):
        q = MockRow(id="q1", question_text="Comments?")
        responses = [MockRow(id="r1", user_id=None, submitted_at="2024-01-01", username=None)]
        env = make_env(db=MockDB([
            make_stmt(first=self._survey_row()),
            make_stmt(all_results=[q]),
            make_stmt(all_results=responses),
            make_stmt(all_results=[]),
        ]))
        r = await worker.api_export_survey("s1", _get_req("/api/surveys/s1/export"), env)
        assert "Anonymous" in r.body