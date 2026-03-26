from workers import Response

from http_utils import CORS

_MIME = {
    "html": "text/html; charset=utf-8",
    "css":  "text/css; charset=utf-8",
    "js":   "application/javascript; charset=utf-8",
    "json": "application/json",
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "svg":  "image/svg+xml",
    "ico":  "image/x-icon",
}


async def serve_static(path: str, env):
    if path in ("/", ""):
        key = "index.html"
    else:
        key = path.lstrip("/")
        if "." not in key.split("/")[-1]:
            key += ".html"

    try:
        content = await env.__STATIC_CONTENT.get(key, "text")
    except Exception:
        content = None

    if content is None:
        try:
            content = await env.__STATIC_CONTENT.get("index.html", "text")
        except Exception:
            content = None

    if content is None:
        return Response(
            "<h1>404 - Not Found</h1>",
            status=404,
            headers={"Content-Type": "text/html"},
        )

    ext  = key.rsplit(".", 1)[-1] if "." in key else "html"
    mime = _MIME.get(ext, "text/plain")
    return Response(content, headers={"Content-Type": mime, **CORS})
