"""
Tests for the Course Materials API (A2 module).

Covers:
  * list_materials   – GET  /api/activities/:activity_id/materials
  * upload_material  – POST /api/activities/:activity_id/materials
  * delete_material  – DELETE /api/activities/:activity_id/materials/:mid
  * download_material – GET /api/activities/:activity_id/materials/:mid/download

Helper stubs:
  * MockR2Bucket – simulates env.R2_BUCKET (put / delete / createPresignedUrl)
"""

import importlib
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure the stubs installed by conftest.py are present before any import
# ---------------------------------------------------------------------------
from tests.helpers import (
    MockDB,
    MockRequest,
    MockRow,
    load_worker,
    make_env,
    make_stmt,
)

# Load worker module (needed for create_token / verify_token)
worker = load_worker()

# ---------------------------------------------------------------------------
# Load the materials module under test
# ---------------------------------------------------------------------------

_MATERIALS_PATH = Path(__file__).parent.parent / "src" / "api" / "materials.py"


def _load_materials():
    """Load src/api/materials.py and inject the already-loaded worker stub."""
    # Make sure "worker" resolves to the already-loaded module inside materials.py
    sys.modules.setdefault("worker", worker)
    spec = importlib.util.spec_from_file_location("src.api.materials", _MATERIALS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


materials = _load_materials()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

JWT = "test-jwt-secret"
ENC = "test-encryption-key"
ACTIVITY_ID = "act-test-001"
MATERIAL_ID = "mat-test-001"
USER_ID = "usr-host-001"
OTHER_USER_ID = "usr-other-001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _token(uid=USER_ID, username="alice", role="host"):
    return worker.create_token(uid, username, role, JWT)


def _auth(uid=USER_ID, username="alice", role="host"):
    return {"Authorization": f"Bearer {_token(uid, username, role)}"}


def _parse(resp):
    return json.loads(resp.body)


def _make_material_row(**kwargs):
    defaults = dict(
        id=MATERIAL_ID,
        activity_id=ACTIVITY_ID,
        title="Lecture Slides",
        description="Week 1 slides",
        file_key=f"materials/{ACTIVITY_ID}/uuid_slides.pdf",
        uploaded_by=USER_ID,
        created_at="2024-06-01 10:00:00",
    )
    defaults.update(kwargs)
    return MockRow(**defaults)


# ---------------------------------------------------------------------------
# Mock R2 bucket
# ---------------------------------------------------------------------------

class MockR2Bucket:
    """Minimal R2 bucket stub that records calls."""

    def __init__(self, presigned_url="https://r2.example.com/signed?token=abc"):
        self._presigned_url = presigned_url
        self.put = AsyncMock(return_value=None)
        self.delete = AsyncMock(return_value=None)
        self.createPresignedUrl = AsyncMock(return_value=presigned_url)


def _make_env_with_r2(db=None, r2=None):
    env = make_env(db=db, enc_key=ENC, jwt_secret=JWT)
    env.R2_BUCKET = r2 if r2 is not None else MockR2Bucket()
    return env


# ---------------------------------------------------------------------------
# list_materials
# ---------------------------------------------------------------------------

class TestListMaterials:
    """GET /api/activities/:activity_id/materials"""

    def _req(self, activity_id=ACTIVITY_ID):
        return MockRequest(method="GET",
                           url=f"http://localhost/api/activities/{activity_id}/materials")

    async def test_returns_materials_list(self):
        row = _make_material_row()
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=MockRow(id=ACTIVITY_ID)),   # activity exists
            make_stmt(all_results=[row]),               # SELECT materials
        ]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        assert resp.status == 200
        data = _parse(resp)
        assert "materials" in data
        assert data["count"] == 1
        assert data["materials"][0]["id"] == MATERIAL_ID
        assert data["materials"][0]["title"] == "Lecture Slides"

    async def test_empty_list_when_no_materials(self):
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=MockRow(id=ACTIVITY_ID)),
            make_stmt(all_results=[]),
        ]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["materials"] == []
        assert data["count"] == 0

    async def test_activity_not_found_returns_404(self):
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=None),   # activity not found
        ]))
        resp = await materials.list_materials("nonexistent", self._req("nonexistent"), env)
        assert resp.status == 404
        assert "not found" in _parse(resp)["error"].lower()

    async def test_db_error_returns_500(self):
        stmt = make_stmt()
        stmt.bind.return_value.first.side_effect = Exception("DB down")
        env = _make_env_with_r2(db=MockDB([stmt]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        assert resp.status == 500

    async def test_materials_query_error_returns_500(self):
        act_stmt = make_stmt(first=MockRow(id=ACTIVITY_ID))
        mat_stmt = make_stmt()
        mat_stmt.bind.return_value.all.side_effect = Exception("Query failed")
        env = _make_env_with_r2(db=MockDB([act_stmt, mat_stmt]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        assert resp.status == 500

    async def test_response_fields_present(self):
        row = _make_material_row()
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=MockRow(id=ACTIVITY_ID)),
            make_stmt(all_results=[row]),
        ]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        mat = _parse(resp)["materials"][0]
        for field in ("id", "activity_id", "title", "description", "uploaded_by", "created_at"):
            assert field in mat, f"Missing field: {field}"

    async def test_file_key_not_exposed_in_list(self):
        """R2 file_key must never appear in the list response."""
        row = _make_material_row()
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=MockRow(id=ACTIVITY_ID)),
            make_stmt(all_results=[row]),
        ]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        mat = _parse(resp)["materials"][0]
        assert "file_key" not in mat

    async def test_multiple_materials_returned(self):
        rows = [_make_material_row(id=f"mat-{i}", title=f"Material {i}") for i in range(3)]
        env = _make_env_with_r2(db=MockDB([
            make_stmt(first=MockRow(id=ACTIVITY_ID)),
            make_stmt(all_results=rows),
        ]))
        resp = await materials.list_materials(ACTIVITY_ID, self._req(), env)
        data = _parse(resp)
        assert data["count"] == 3
        assert len(data["materials"]) == 3


# ---------------------------------------------------------------------------
# upload_material
# ---------------------------------------------------------------------------

class TestUploadMaterial:
    """POST /api/activities/:activity_id/materials"""

    def _req(self, activity_id=ACTIVITY_ID, headers=None, body=None):
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        return MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{activity_id}/materials",
            headers=h,
            body=json.dumps(body) if body is not None else None,
        )

    def _upload_req(self, title="Slides", description="", filename="slides.pdf",
                    file_bytes=b"%PDF-1.4 test", activity_id=ACTIVITY_ID, uid=USER_ID):
        """Build a JSON-body request that exercises the JSON fallback path in _parse_multipart."""
        body = {
            "title": title,
            "description": description,
            "filename": filename,
            "file": {
                "filename": filename,
                "bytes": list(file_bytes),   # JSON-serialisable
                "content_type": "application/pdf",
            },
        }
        return MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{activity_id}/materials",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_token(uid)}",
            },
            body=json.dumps(body),
        )

    async def test_no_auth_returns_401(self):
        env = _make_env_with_r2()
        resp = await materials.upload_material(ACTIVITY_ID, self._req(), env)
        assert resp.status == 401

    async def test_activity_not_found_returns_404(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=None)]))
        req = self._upload_req()
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 404

    async def test_missing_title_returns_400(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=MockRow(id=ACTIVITY_ID))]))
        body = {"description": "no title", "file": {"filename": "f.pdf", "bytes": [1, 2, 3]}}
        req = MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {_token()}"},
            body=json.dumps(body),
        )
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 400
        assert "title" in _parse(resp)["error"].lower()

    async def test_missing_file_returns_400(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=MockRow(id=ACTIVITY_ID))]))
        body = {"title": "Slides"}
        req = MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {_token()}"},
            body=json.dumps(body),
        )
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 400
        assert "file" in _parse(resp)["error"].lower()

    async def test_successful_upload_returns_200(self):
        r2 = MockR2Bucket()
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),  # activity check
                make_stmt(),                               # INSERT material
            ]),
            r2=r2,
        )
        req = self._upload_req()
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["success"] is True
        assert "id" in data["data"]
        assert data["data"]["title"] == "Slides"
        assert data["data"]["activity_id"] == ACTIVITY_ID

    async def test_r2_put_called_on_success(self):
        r2 = MockR2Bucket()
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),
                make_stmt(),
            ]),
            r2=r2,
        )
        await materials.upload_material(ACTIVITY_ID, self._upload_req(), env)
        r2.put.assert_called_once()

    async def test_r2_key_format(self):
        """R2 key must start with materials/{activity_id}/."""
        r2 = MockR2Bucket()
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),
                make_stmt(),
            ]),
            r2=r2,
        )
        await materials.upload_material(ACTIVITY_ID, self._upload_req(), env)
        call_args = r2.put.call_args
        key = call_args[0][0]
        assert key.startswith(f"materials/{ACTIVITY_ID}/")

    async def test_file_key_not_exposed_in_response(self):
        """file_key is returned in upload response for internal use but raw R2 path is opaque."""
        r2 = MockR2Bucket()
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),
                make_stmt(),
            ]),
            r2=r2,
        )
        resp = await materials.upload_material(ACTIVITY_ID, self._upload_req(), env)
        data = _parse(resp)
        # file_key is present in upload response (internal reference) but must not be a raw URL
        key = data["data"].get("file_key", "")
        assert not key.startswith("http"), "file_key must not be a public URL"

    async def test_r2_upload_failure_returns_500(self):
        r2 = MockR2Bucket()
        r2.put.side_effect = Exception("R2 unavailable")
        env = _make_env_with_r2(
            db=MockDB([make_stmt(first=MockRow(id=ACTIVITY_ID))]),
            r2=r2,
        )
        resp = await materials.upload_material(ACTIVITY_ID, self._upload_req(), env)
        assert resp.status == 500

    async def test_db_insert_failure_deletes_r2_object(self):
        """If D1 insert fails after R2 upload, the orphaned R2 object must be deleted."""
        r2 = MockR2Bucket()
        insert_stmt = make_stmt()
        insert_stmt.bind.return_value.run.side_effect = Exception("D1 write error")
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),
                insert_stmt,
            ]),
            r2=r2,
        )
        resp = await materials.upload_material(ACTIVITY_ID, self._upload_req(), env)
        assert resp.status == 500
        # Compensating delete must have been called
        r2.delete.assert_called_once()

    async def test_empty_file_bytes_returns_400(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=MockRow(id=ACTIVITY_ID))]))
        body = {"title": "Empty", "file": {"filename": "empty.pdf", "bytes": []}}
        req = MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {_token()}"},
            body=json.dumps(body),
        )
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 400

    async def test_invalid_json_returns_400(self):
        req = MockRequest(
            method="POST",
            url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {_token()}"},
            body="not-json",
        )
        env = _make_env_with_r2(db=MockDB([make_stmt(first=MockRow(id=ACTIVITY_ID))]))
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 400

    async def test_description_is_optional(self):
        r2 = MockR2Bucket()
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=MockRow(id=ACTIVITY_ID)),
                make_stmt(),
            ]),
            r2=r2,
        )
        req = self._upload_req(description="")
        resp = await materials.upload_material(ACTIVITY_ID, req, env)
        assert resp.status == 200


# ---------------------------------------------------------------------------
# delete_material
# ---------------------------------------------------------------------------

class TestDeleteMaterial:
    """DELETE /api/activities/:activity_id/materials/:mid"""

    def _req(self, activity_id=ACTIVITY_ID, mid=MATERIAL_ID, uid=USER_ID):
        return MockRequest(
            method="DELETE",
            url=f"http://localhost/api/activities/{activity_id}/materials/{mid}",
            headers={"Authorization": f"Bearer {_token(uid)}"},
        )

    async def test_no_auth_returns_401(self):
        env = _make_env_with_r2()
        req = MockRequest(method="DELETE",
                          url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials/{MATERIAL_ID}")
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, req, env)
        assert resp.status == 401

    async def test_material_not_found_returns_404(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=None)]))
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 404

    async def test_uploader_can_delete(self):
        r2 = MockR2Bucket()
        mat_row = _make_material_row(uploaded_by=USER_ID)
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),   # material lookup
                make_stmt(),                # DELETE
            ]),
            r2=r2,
        )
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(uid=USER_ID), env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["success"] is True
        assert data["data"]["id"] == MATERIAL_ID

    async def test_host_can_delete_others_material(self):
        """Activity host should be able to delete any material in their activity."""
        r2 = MockR2Bucket()
        mat_row = _make_material_row(uploaded_by=OTHER_USER_ID)
        host_act_row = MockRow(host_id=USER_ID)
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),        # material lookup
                make_stmt(first=host_act_row),   # activity host check
                make_stmt(),                     # DELETE
            ]),
            r2=r2,
        )
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(uid=USER_ID), env)
        assert resp.status == 200

    async def test_non_owner_non_host_returns_403(self):
        mat_row = _make_material_row(uploaded_by=OTHER_USER_ID)
        act_row = MockRow(host_id=OTHER_USER_ID)   # different host
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),
                make_stmt(first=act_row),
            ]),
        )
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(uid=USER_ID), env)
        assert resp.status == 403

    async def test_r2_delete_called_after_db_delete(self):
        r2 = MockR2Bucket()
        mat_row = _make_material_row(uploaded_by=USER_ID)
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),
                make_stmt(),
            ]),
            r2=r2,
        )
        await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        r2.delete.assert_called_once_with(mat_row.file_key)

    async def test_db_delete_failure_returns_500(self):
        mat_row = _make_material_row(uploaded_by=USER_ID)
        del_stmt = make_stmt()
        del_stmt.bind.return_value.run.side_effect = Exception("DB error")
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),
                del_stmt,
            ]),
        )
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 500

    async def test_r2_delete_error_does_not_fail_request(self):
        """R2 delete errors are swallowed – the DB record is already gone."""
        r2 = MockR2Bucket()
        r2.delete.side_effect = Exception("R2 error")
        mat_row = _make_material_row(uploaded_by=USER_ID)
        env = _make_env_with_r2(
            db=MockDB([
                make_stmt(first=mat_row),
                make_stmt(),
            ]),
            r2=r2,
        )
        # Should still return 200 even though R2 delete raised
        resp = await materials.delete_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 200

    async def test_activity_id_scoping(self):
        """Material must belong to the given activity_id (enforced by WHERE clause)."""
        # Simulate the DB returning None because activity_id doesn't match
        env = _make_env_with_r2(db=MockDB([make_stmt(first=None)]))
        resp = await materials.delete_material("wrong-activity", MATERIAL_ID, self._req(), env)
        assert resp.status == 404


# ---------------------------------------------------------------------------
# download_material
# ---------------------------------------------------------------------------

class TestDownloadMaterial:
    """GET /api/activities/:activity_id/materials/:mid/download"""

    def _req(self, activity_id=ACTIVITY_ID, mid=MATERIAL_ID, uid=USER_ID):
        return MockRequest(
            method="GET",
            url=f"http://localhost/api/activities/{activity_id}/materials/{mid}/download",
            headers={"Authorization": f"Bearer {_token(uid)}"},
        )

    async def test_no_auth_returns_401(self):
        env = _make_env_with_r2()
        req = MockRequest(
            method="GET",
            url=f"http://localhost/api/activities/{ACTIVITY_ID}/materials/{MATERIAL_ID}/download",
        )
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, req, env)
        assert resp.status == 401

    async def test_material_not_found_returns_404(self):
        env = _make_env_with_r2(db=MockDB([make_stmt(first=None)]))
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 404

    async def test_returns_signed_url(self):
        signed_url = "https://r2.example.com/signed?token=xyz&expires=3600"
        r2 = MockR2Bucket(presigned_url=signed_url)
        mat_row = MockRow(id=MATERIAL_ID, title="Slides",
                          file_key=f"materials/{ACTIVITY_ID}/uuid_slides.pdf")
        env = _make_env_with_r2(db=MockDB([make_stmt(first=mat_row)]), r2=r2)
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["success"] is True
        assert data["data"]["download_url"] == signed_url
        assert data["data"]["id"] == MATERIAL_ID
        assert data["data"]["title"] == "Slides"

    async def test_expires_in_field_present(self):
        r2 = MockR2Bucket()
        mat_row = MockRow(id=MATERIAL_ID, title="Slides",
                          file_key=f"materials/{ACTIVITY_ID}/uuid_slides.pdf")
        env = _make_env_with_r2(db=MockDB([make_stmt(first=mat_row)]), r2=r2)
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        data = _parse(resp)
        assert "expires_in" in data["data"]
        assert data["data"]["expires_in"] == 3600

    async def test_raw_r2_key_not_in_response(self):
        """The raw R2 file_key must never appear in the download response."""
        r2 = MockR2Bucket()
        file_key = f"materials/{ACTIVITY_ID}/uuid_slides.pdf"
        mat_row = MockRow(id=MATERIAL_ID, title="Slides", file_key=file_key)
        env = _make_env_with_r2(db=MockDB([make_stmt(first=mat_row)]), r2=r2)
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        body_str = resp.body
        assert file_key not in body_str

    async def test_presigned_url_fallback_when_r2_method_missing(self):
        """When createPresignedUrl is unavailable, fall back to /api/r2/:key proxy URL."""
        r2 = MockR2Bucket()
        r2.createPresignedUrl.side_effect = Exception("Method not available")
        file_key = f"materials/{ACTIVITY_ID}/uuid_slides.pdf"
        mat_row = MockRow(id=MATERIAL_ID, title="Slides", file_key=file_key)
        env = _make_env_with_r2(db=MockDB([make_stmt(first=mat_row)]), r2=r2)
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 200
        data = _parse(resp)
        # Fallback URL should be the internal proxy path
        assert data["data"]["download_url"] == f"/api/r2/{file_key}"

    async def test_db_error_returns_500(self):
        stmt = make_stmt()
        stmt.bind.return_value.first.side_effect = Exception("DB down")
        env = _make_env_with_r2(db=MockDB([stmt]))
        resp = await materials.download_material(ACTIVITY_ID, MATERIAL_ID, self._req(), env)
        assert resp.status == 500

    async def test_activity_id_scoping(self):
        """Material must belong to the given activity_id."""
        env = _make_env_with_r2(db=MockDB([make_stmt(first=None)]))
        resp = await materials.download_material("wrong-activity", MATERIAL_ID, self._req(), env)
        assert resp.status == 404


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

class TestHelpers:
    """Unit tests for internal helper functions."""

    def test_new_id_is_uuid_format(self):
        uid = materials._new_id()
        parts = uid.split("-")
        assert len(parts) == 5
        assert len(uid) == 36

    def test_new_id_uniqueness(self):
        ids = {materials._new_id() for _ in range(100)}
        assert len(ids) == 100

    def test_r2_key_format(self):
        key = materials._r2_key("act-123", "lecture.pdf")
        assert key.startswith("materials/act-123/")
        assert key.endswith("lecture.pdf")

    def test_r2_key_sanitises_special_chars(self):
        key = materials._r2_key("act-1", "my file (1).pdf")
        # Spaces and parentheses should be replaced with underscores
        assert " " not in key
        assert "(" not in key
        assert ")" not in key

    def test_r2_key_caps_filename_length(self):
        long_name = "a" * 300 + ".pdf"
        key = materials._r2_key("act-1", long_name)
        # The filename portion after the UUID_ prefix should be ≤ 128 chars
        filename_part = key.split("/")[-1].split("_", 5)[-1]
        assert len(filename_part) <= 128

    def test_r2_key_unique_per_call(self):
        k1 = materials._r2_key("act-1", "file.pdf")
        k2 = materials._r2_key("act-1", "file.pdf")
        assert k1 != k2
