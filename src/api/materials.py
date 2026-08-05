"""
Course Materials API – A2 module
=================================
Endpoints:
  GET    /api/activities/:activity_id/materials
  POST   /api/activities/:activity_id/materials
  DELETE /api/activities/:activity_id/materials/:mid
  GET    /api/activities/:activity_id/materials/:mid/download

Storage:  Cloudflare R2  (env.R2_BUCKET)
Database: Cloudflare D1  (env.DB)
Auth:     HMAC-SHA256 stateless tokens (verify_token from worker)
"""

import json
import os


# ---------------------------------------------------------------------------
# Internal helpers (imported lazily from worker to avoid circular imports)
# ---------------------------------------------------------------------------

def _worker():
    """Return the worker module.  Imported once and cached."""
    import importlib, sys
    if "worker" in sys.modules:
        return sys.modules["worker"]
    # When running inside the CF runtime the module is already loaded as
    # the top-level entry-point; fall back to a direct import for tests.
    return importlib.import_module("worker")


def _filename_from_key(file_key: str) -> str:
    """Extract original filename from R2 key (materials/{act_id}/{uuid}_{filename})."""
    raw_name = file_key.split("/")[-1]
    return raw_name[37:] if len(raw_name) > 37 else raw_name


def _new_id() -> str:
    """Generate a UUID-v4 using os.urandom (no stdlib uuid needed)."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40   # version 4
    b[8] = (b[8] & 0x3F) | 0x80   # RFC 4122 variant
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _r2_key(activity_id: str, filename: str) -> str:
    """Build a deterministic, collision-resistant R2 object key.

    Format: ``materials/{activity_id}/{uuid}_{sanitised_filename}``

    The UUID prefix guarantees uniqueness even when the same filename is
    uploaded twice.  The sanitised filename is kept for human readability
    inside the R2 bucket.
    """
    safe_name = "".join(
        c if (c.isalnum() or c in "-_.") else "_"
        for c in filename
    )[:128]  # cap at 128 chars to stay well within R2 key limits
    return f"materials/{activity_id}/{_new_id()}_{safe_name}"


async def _parse_multipart(req):
    """
    Parse a multipart/form-data request using the CF Workers FormData API.

    Returns ``(fields_dict, error_response | None)`` where *fields_dict*
    maps field names to either a string value (text fields) or a dict
    ``{"filename": str, "bytes": bytes}`` (file fields).

    Falls back to a plain JSON body when the Content-Type is
    ``application/json`` so that unit tests can exercise the handler
    without constructing real multipart payloads.
    """
    w = _worker()
    content_type = (req.headers.get("Content-Type") or
                    req.headers.get("content-type") or "")

    # ---- JSON fallback (used by unit tests) --------------------------------
    if "application/json" in content_type:
        try:
            text = await req.text()
            body = json.loads(text)
        except Exception:
            return None, w.err("Invalid JSON body", 400)
        if not isinstance(body, dict):
            return None, w.err("JSON body must be an object", 400)
        return body, None

    # ---- Real multipart (CF Workers runtime) --------------------------------
    try:
        form_data = await req.formData()
    except Exception:
        return None, w.err("Failed to parse multipart form data", 400)

    fields = {}
    try:
        # formData() returns a JS FormData object; iterate its entries.
        for key, value in form_data.entries():
            # File entries expose a .name attribute (the original filename).
            filename = getattr(value, "name", None) or getattr(value, "filename", None)
            if filename is not None:
                # It's a File/Blob – read raw bytes.
                try:
                    arr_buf = await value.arrayBuffer()
                    import js  
                    raw = bytes(js.Uint8Array.new(arr_buf))
                except Exception:
                    raw = b""
                fields[key] = {"filename": filename, "bytes": raw}
            else:
                fields[key] = str(value)
    except Exception:
        # Fallback: try the dict-like .get() interface some runtimes expose.
        for field_name in ("title", "description", "file"):
            val = form_data.get(field_name)
            if val is None:
                continue
            filename = getattr(val, "name", None) or getattr(val, "filename", None)
            if filename is not None:
                try:
                    arr_buf = await val.arrayBuffer()
                    import js  
                    raw = bytes(js.Uint8Array.new(arr_buf))
                except Exception:
                    raw = b""
                fields[field_name] = {"filename": filename, "bytes": raw}
            else:
                fields[field_name] = str(val)

    return fields, None


def _r2_bucket(env):
    """Return the R2 bucket binding (supports MY_BUCKET, R2_BUCKET, or R2)."""
    env_dict = getattr(env, "__dict__", {})
    if "MY_BUCKET" in env_dict:
        return env_dict["MY_BUCKET"]
    if "R2_BUCKET" in env_dict:
        return env_dict["R2_BUCKET"]
    if "R2" in env_dict:
        return env_dict["R2"]
    bucket = (
        getattr(env, "MY_BUCKET", None)
        or getattr(env, "R2_BUCKET", None)
        or getattr(env, "R2", None)
    )
    if bucket is None:
        raise AttributeError("No R2 bucket binding found on env (checked MY_BUCKET, R2_BUCKET, R2).")
    return bucket


async def _upload_to_r2(env, key: str, data: bytes, content_type: str = "application/octet-stream",
                        original_filename: str = ""):
    """Upload *data* to R2 under *key*.

    Stores ``Content-Type`` and ``Content-Disposition`` in R2 httpMetadata so
    that presigned download URLs automatically serve the correct filename and
    MIME type without needing a proxy.

    Uses ``_r2_bucket(env).put(key, data, options)`` which is the standard
    Cloudflare Workers R2 binding API.
    """
    bucket = _r2_bucket(env)
    try:
        from pyodide.ffi import to_js  # noqa: PLC0415 – CF runtime only
        import js                       # noqa: PLC0415
        http_meta = {"contentType": content_type}
        if original_filename:
            # Sanitize filename for Content-Disposition to avoid header injection.
            safe_fn = (
                str(original_filename)
                .replace("\\", "_")
                .replace('"', "_")
                .replace("\r", "")
                .replace("\n", "")
            )
            http_meta["contentDisposition"] = f'attachment; filename="{safe_fn}"'
        options = to_js(
            {"httpMetadata": http_meta},
            dict_converter=js.Object.fromEntries,
        )
        await bucket.put(key, to_js(data, create_pyproxies=False), options)
    except ImportError:
        # Unit-test environment: bucket is a MagicMock / AsyncMock.
        await bucket.put(key, data)


async def _delete_from_r2(env, key: str):
    """Delete the object at *key* from R2 (best-effort; errors are swallowed)."""
    try:
        bucket = _r2_bucket(env)
        await bucket.delete(key)
    except Exception as exc:
        w = _worker()
        await w.capture_exception(exc, _env=env, where="materials._delete_from_r2")


async def _generate_download_url(env, key: str) -> str:
    """Return a time-limited signed URL for *key* from R2.

    Cloudflare R2 supports ``createPresignedUrl`` on the bucket binding.
    If the binding does not expose that method (e.g. older SDK or unit
    tests), we fall back to a plain ``/api/r2/{key}`` path that the
    worker can proxy.
    """
    try:
        bucket = _r2_bucket(env)
        # CF Workers R2 binding: bucket.createPresignedUrl(key, {expiresIn})
        url = await bucket.createPresignedUrl(key, {"expiresIn": 3600})
        return str(url)
    except Exception:
        pass
    # Fallback: internal proxy URL (worker must implement GET /api/r2/:key)
    return f"/api/r2/{key}"


# ---------------------------------------------------------------------------
# Endpoint handlers
# ---------------------------------------------------------------------------

async def list_materials(activity_id: str, req, env):
    """GET /api/activities/:activity_id/materials

    Returns all materials for the given activity ordered by created_at DESC.
    Authentication is optional – public read access is allowed so that
    unenrolled visitors can see what materials an activity offers.
    """
    w = _worker()

    # Validate activity exists
    try:
        act = await env.DB.prepare(
            "SELECT id FROM activities WHERE id = ?"
        ).bind(activity_id).first()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.list.activity_lookup")
        return w.err("Database error", 500)

    if not act:
        return w.err("Activity not found", 404)

    try:
        res = await env.DB.prepare(
            "SELECT id, activity_id, title, description, uploaded_by, created_at"
            " FROM course_materials"
            " WHERE activity_id = ?"
            " ORDER BY created_at DESC"
        ).bind(activity_id).all()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.list.query")
        return w.err("Failed to fetch materials", 500)

    materials = []
    for row in res.results or []:
        materials.append({
            "id":          row.id,
            "activity_id": row.activity_id,
            "title":       row.title,
            "description": row.description or "",
            "uploaded_by": row.uploaded_by,
            "created_at":  row.created_at,
        })

    return w.json_resp({"materials": materials, "count": len(materials)})


async def upload_material(activity_id: str, req, env):
    """POST /api/activities/:activity_id/materials

    Accepts multipart/form-data with fields:
      - title       (required, text)
      - description (optional, text)
      - file        (required, binary)

    Uploads the file to R2 and stores metadata in D1.
    Requires authentication.
    """
    w = _worker()

    user = w.verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return w.err("Authentication required", 401)

    # Validate activity exists and user is host
    try:
        act = await env.DB.prepare(
            "SELECT id, host_id FROM activities WHERE id = ?"
        ).bind(activity_id).first()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.upload.activity_lookup")
        return w.err("Database error", 500)

    if not act:
        return w.err("Activity not found", 404)

    host_id = getattr(act, "host_id", None)
    if host_id and host_id != user["id"]:
        return w.err("Only the activity creator can upload materials", 403)

    # Parse multipart body
    fields, parse_err = await _parse_multipart(req)
    if parse_err:
        return parse_err

    title = (fields.get("title") or "").strip() if isinstance(fields.get("title"), str) else ""
    description = (fields.get("description") or "").strip() if isinstance(fields.get("description"), str) else ""

    if not title:
        return w.err("title is required", 400)

    file_field = fields.get("file")
    if not file_field:
        return w.err("file is required", 400)

    # Support both dict (multipart/JSON) and raw bytes (test injection)
    if isinstance(file_field, dict):
        filename = file_field.get("filename") or "upload"
        raw_bytes = file_field.get("bytes") or b""
        # JSON fallback may provide a list of ints; normalise to bytes.
        if isinstance(raw_bytes, list):
            try:
                file_bytes = bytes(raw_bytes)
            except Exception:
                return w.err("Invalid file bytes", 400)
        elif isinstance(raw_bytes, (bytes, bytearray)):
            file_bytes = bytes(raw_bytes)
        else:
            return w.err("Invalid file bytes", 400)
        content_type = file_field.get("content_type") or "application/octet-stream"
    elif isinstance(file_field, (bytes, bytearray)):
        filename = fields.get("filename") or "upload"
        file_bytes = bytes(file_field)
        content_type = "application/octet-stream"
    else:
        return w.err("Invalid file field", 400)

    if not file_bytes:
        return w.err("Uploaded file is empty", 400)

    # 50MB file size guard
    MAX_FILE_SIZE = 50 * 1024 * 1024
    if len(file_bytes) > MAX_FILE_SIZE:
        return w.err("File size exceeds 50MB limit", 400)

    # Build R2 key and upload
    r2_key = _r2_key(activity_id, filename)
    try:
        await _upload_to_r2(env, r2_key, file_bytes, content_type, original_filename=filename)
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.upload.r2_put")
        return w.err("File upload failed — please try again", 500)

    # Persist metadata in D1
    mid = _new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO course_materials"
            " (id, activity_id, title, description, file_key, uploaded_by)"
            " VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(mid, activity_id, title, description, r2_key, user["id"]).run()
    except Exception as exc:
        # Compensating action: remove the orphaned R2 object
        await _delete_from_r2(env, r2_key)
        await w.capture_exception(exc, req, env, "materials.upload.db_insert")
        return w.err("Failed to save material metadata — please try again", 500)

    return w.ok(
        {
            "id":          mid,
            "activity_id": activity_id,
            "title":       title,
            "description": description,
            "file_key":    r2_key,   # internal key – not a public URL
        },
        "Material uploaded successfully",
    )


async def delete_material(activity_id: str, mid: str, req, env):
    """DELETE /api/activities/:activity_id/materials/:mid

    Deletes the material record from D1 and the file from R2.
    Only the uploader or the activity host may delete a material.
    """
    w = _worker()

    user = w.verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return w.err("Authentication required", 401)

    # Fetch the material (also validates activity_id matches)
    try:
        row = await env.DB.prepare(
            "SELECT id, activity_id, file_key, uploaded_by"
            " FROM course_materials"
            " WHERE id = ? AND activity_id = ?"
        ).bind(mid, activity_id).first()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.delete.lookup")
        return w.err("Database error", 500)

    if not row:
        return w.err("Material not found", 404)

    # Authorisation: uploader OR activity host may delete
    is_uploader = (row.uploaded_by == user["id"])
    is_host = False
    if not is_uploader:
        try:
            act = await env.DB.prepare(
                "SELECT host_id FROM activities WHERE id = ?"
            ).bind(activity_id).first()
            is_host = bool(act and act.host_id == user["id"])
        except Exception as exc:
            await w.capture_exception(exc, req, env, "materials.delete.host_check")

    if not is_uploader and not is_host:
        return w.err("Permission denied", 403)

    # Delete from D1 first (so the record is gone even if R2 delete lags)
    try:
        await env.DB.prepare(
            "DELETE FROM course_materials WHERE id = ?"
        ).bind(mid).run()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.delete.db_delete")
        return w.err("Failed to delete material record", 500)

    # Best-effort R2 deletion (errors are logged but do not fail the request)
    await _delete_from_r2(env, row.file_key)

    return w.ok({"id": mid}, "Material deleted successfully")


async def update_material(activity_id: str, mid: str, req, env):
    """PATCH /api/activities/:activity_id/materials/:mid

    Updates the title and/or description of an existing material.
    Only the uploader or the activity host may edit a material.
    """
    w = _worker()

    user = w.verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return w.err("Authentication required", 401)

    # Fetch the material (also validates activity_id matches)
    try:
        row = await env.DB.prepare(
            "SELECT id, activity_id, uploaded_by"
            " FROM course_materials"
            " WHERE id = ? AND activity_id = ?"
        ).bind(mid, activity_id).first()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.update.lookup")
        return w.err("Database error", 500)

    if not row:
        return w.err("Material not found", 404)

    # Authorisation: uploader OR activity host may edit
    is_uploader = (row.uploaded_by == user["id"])
    is_host = False
    if not is_uploader:
        try:
            act = await env.DB.prepare(
                "SELECT host_id FROM activities WHERE id = ?"
            ).bind(activity_id).first()
            is_host = bool(act and act.host_id == user["id"])
        except Exception as exc:
            await w.capture_exception(exc, req, env, "materials.update.host_check")

    if not is_uploader and not is_host:
        return w.err("Permission denied", 403)

    # Parse JSON body
    body, parse_err = await w.parse_json_object(req)
    if parse_err:
        return parse_err

    title       = (body.get("title") or "").strip() if isinstance(body.get("title"), str) else ""
    description = (body.get("description") or "").strip() if isinstance(body.get("description"), str) else ""

    if not title:
        return w.err("title is required", 400)

    try:
        await env.DB.prepare(
            "UPDATE course_materials SET title = ?, description = ? WHERE id = ?"
        ).bind(title, description, mid).run()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.update.db_update")
        return w.err("Failed to update material", 500)

    return w.ok(
        {"id": mid, "title": title, "description": description},
        "Material updated successfully",
    )


async def download_material(activity_id: str, mid: str, req, env):
    """GET /api/activities/:activity_id/materials/:mid/download

    Returns a time-limited signed URL for the material's R2 object.
    Prefer presigned R2 URLs; if presigning isn't available, falls back to
    the authenticated ``/api/r2/{key}`` proxy implemented in the worker.
    Requires authentication.
    """
    w = _worker()

    user = w.verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return w.err("Authentication required", 401)

    # Fetch material (validates activity_id scope)
    try:
        row = await env.DB.prepare(
            "SELECT id, title, file_key"
            " FROM course_materials"
            " WHERE id = ? AND activity_id = ?"
        ).bind(mid, activity_id).first()
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.download.lookup")
        return w.err("Database error", 500)

    if not row:
        return w.err("Material not found", 404)

    # Generate a signed / temporary download URL
    try:
        download_url = await _generate_download_url(env, row.file_key)
    except Exception as exc:
        await w.capture_exception(exc, req, env, "materials.download.url_gen")
        return w.err("Failed to generate download URL", 500)

    # Derive the original filename from the R2 key
    original_filename = _filename_from_key(row.file_key)

    return w.ok(
        {
            "id":           row.id,
            "title":        row.title,
            "filename":     original_filename,
            "download_url": download_url,
            "expires_in":   3600,  # seconds
        },
        "Download URL generated",
    )
