"""
Admin-only API handlers live here.
"""

from http_utils import is_basic_auth_valid, json_resp, unauthorized_basic

async def api_admin_table_counts(req, env):
    if not is_basic_auth_valid(req, env):
        return unauthorized_basic()

    tables_res = await env.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all()

    counts = []
    for row in tables_res.results or []:
        table_name = row.name
        # Table names come from sqlite_master and are quoted to avoid SQL injection.
        count_row = await env.DB.prepare(
            f'SELECT COUNT(*) AS cnt FROM "{table_name.replace(chr(34), chr(34) + chr(34))}"'
        ).first()
        counts.append({"table": table_name, "count": count_row.cnt if count_row else 0})

    return json_resp({"tables": counts})