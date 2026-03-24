"""
Database schema and seed helpers live here.
"""

from security_utils import blind_index, encrypt, hash_password

# ---------------------------------------------------------------------------
# DDL - full schema (mirrors schema.sql)
# ---------------------------------------------------------------------------

_DDL = [
    # Users - all PII encrypted; HMAC blind indexes for O(1) lookups
    """CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        username_hash TEXT NOT NULL UNIQUE,
        email_hash    TEXT NOT NULL UNIQUE,
        name          TEXT NOT NULL,
        username      TEXT NOT NULL,
        email         TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    )""",
    # Activities
    """CREATE TABLE IF NOT EXISTS activities (
        id            TEXT PRIMARY KEY,
        title         TEXT NOT NULL,
        description   TEXT,
        type          TEXT NOT NULL DEFAULT 'course',
        format        TEXT NOT NULL DEFAULT 'self_paced',
        schedule_type TEXT NOT NULL DEFAULT 'ongoing',
        host_id       TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES users(id)
    )""",
    # Sessions
    """CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL,
        title       TEXT,
        description TEXT,
        start_time  TEXT,
        end_time    TEXT,
        location    TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (activity_id) REFERENCES activities(id)
    )""",
    # Enrollments
    """CREATE TABLE IF NOT EXISTS enrollments (
        id          TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'participant',
        status      TEXT NOT NULL DEFAULT 'active',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (activity_id, user_id),
        FOREIGN KEY (activity_id) REFERENCES activities(id),
        FOREIGN KEY (user_id)     REFERENCES users(id)
    )""",
    # Session attendance
    """CREATE TABLE IF NOT EXISTS session_attendance (
        id         TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id    TEXT NOT NULL,
        status     TEXT NOT NULL DEFAULT 'registered',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (session_id, user_id),
        FOREIGN KEY (session_id) REFERENCES sessions(id),
        FOREIGN KEY (user_id)    REFERENCES users(id)
    )""",
    # Tags
    """CREATE TABLE IF NOT EXISTS tags (
        id   TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    )""",
    # Activity-tag junction
    """CREATE TABLE IF NOT EXISTS activity_tags (
        activity_id TEXT NOT NULL,
        tag_id      TEXT NOT NULL,
        PRIMARY KEY (activity_id, tag_id),
        FOREIGN KEY (activity_id) REFERENCES activities(id),
        FOREIGN KEY (tag_id)      REFERENCES tags(id)
    )""",
    # Indexes
    "CREATE INDEX IF NOT EXISTS idx_activities_host      ON activities(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_enrollments_activity ON enrollments(activity_id)",
    "CREATE INDEX IF NOT EXISTS idx_enrollments_user     ON enrollments(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_activity    ON sessions(activity_id)",
    "CREATE INDEX IF NOT EXISTS idx_sa_session           ON session_attendance(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sa_user              ON session_attendance(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_at_activity          ON activity_tags(activity_id)",
]


async def init_db(env):
    for sql in _DDL:
        await env.DB.prepare(sql).run()


# ---------------------------------------------------------------------------
# Sample-data seeding
# ---------------------------------------------------------------------------

async def seed_db(env, enc_key: str):
    # ---- users ---------------------------------------------------------------
    seed_users = [
        ("alice",   "alice@example.com",   "password123", "host",   "Alice Chen"),
        ("bob",     "bob@example.com",     "password123", "host",   "Bob Martinez"),
        ("charlie", "charlie@example.com", "password123", "member", "Charlie Kim"),
        ("diana",   "diana@example.com",   "password123", "member", "Diana Patel"),
    ]
    uid_map = {}
    for uname, email, pw, role, display in seed_users:
        uid = f"usr-{uname}"
        uid_map[uname] = uid
        try:
            await env.DB.prepare(
                "INSERT INTO users "
                "(id,username_hash,email_hash,name,username,email,password_hash,role)"
                " VALUES (?,?,?,?,?,?,?,?)"
            ).bind(
                uid,
                blind_index(uname, enc_key),
                blind_index(email, enc_key),
                encrypt(display,  enc_key),
                encrypt(uname,    enc_key),
                encrypt(email,    enc_key),
                hash_password(pw, uname),
                encrypt(role,     enc_key),
            ).run()
        except Exception:
            pass  # already seeded

    aid = uid_map["alice"]
    bid = uid_map["bob"]
    cid = uid_map["charlie"]
    did = uid_map["diana"]

    # ---- tags ----------------------------------------------------------------
    tag_rows = [
        ("tag-python", "Python"),
        ("tag-js",     "JavaScript"),
        ("tag-data",   "Data Science"),
        ("tag-ml",     "Machine Learning"),
        ("tag-webdev", "Web Development"),
        ("tag-db",     "Databases"),
        ("tag-cloud",  "Cloud"),
    ]
    for tid, tname in tag_rows:
        try:
            await env.DB.prepare(
                "INSERT INTO tags (id,name) VALUES (?,?)"
            ).bind(tid, tname).run()
        except Exception:
            pass

    # ---- activities ----------------------------------------------------------
    act_rows = [
        (
            "act-py-begin", "Python for Beginners",
            "Learn Python programming from scratch. Master variables, loops, "
            "functions, and object-oriented design in this hands-on course.",
            "course", "self_paced", "ongoing", aid,
            ["tag-python"],
        ),
        (
            "act-js-meetup", "JavaScript Developers Meetup",
            "Monthly meetup for JavaScript enthusiasts. Share projects, "
            "discuss new frameworks, and network with fellow devs.",
            "meetup", "live", "recurring", bid,
            ["tag-js", "tag-webdev"],
        ),
        (
            "act-ds-workshop", "Data Science Workshop",
            "Hands-on workshop covering data wrangling with pandas, "
            "visualisation with matplotlib, and intro to machine learning.",
            "workshop", "live", "multi_session", aid,
            ["tag-data", "tag-python"],
        ),
        (
            "act-ml-study", "Machine Learning Study Group",
            "Collaborative study group working through ML concepts, "
            "reading papers, and implementing algorithms together.",
            "course", "hybrid", "recurring", bid,
            ["tag-ml", "tag-python"],
        ),
        (
            "act-webdev", "Web Dev Fundamentals",
            "Build modern responsive websites with HTML5, CSS3, and JavaScript. "
            "Covers Flexbox, Grid, fetch API, and accessible design.",
            "course", "self_paced", "ongoing", aid,
            ["tag-webdev", "tag-js"],
        ),
        (
            "act-db-design", "Database Design & SQL",
            "Design normalised relational schemas, write complex SQL queries, "
            "use indexes for speed, and understand transactions.",
            "workshop", "live", "one_time", bid,
            ["tag-db"],
        ),
    ]
    for act_id, title, desc, atype, fmt, sched, host_id, tags in act_rows:
        try:
            await env.DB.prepare(
                "INSERT INTO activities "
                "(id,title,description,type,format,schedule_type,host_id)"
                " VALUES (?,?,?,?,?,?,?)"
            ).bind(
                act_id, title, encrypt(desc, enc_key),
                atype, fmt, sched, host_id
            ).run()
        except Exception:
            pass
        for tag_id in tags:
            try:
                await env.DB.prepare(
                    "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id)"
                    " VALUES (?,?)"
                ).bind(act_id, tag_id).run()
            except Exception:
                pass

    # ---- sessions for live/recurring activities ------------------------------
    ses_rows = [
        ("ses-js-1", "act-js-meetup",
         "April Meetup", "Q1 retro and React 19 deep-dive",
         "2024-04-15 18:00", "2024-04-15 21:00", "Tech Hub, 123 Main St, SF"),
        ("ses-js-2", "act-js-meetup",
         "May Meetup", "TypeScript 5.4 and what's new in Node 22",
         "2024-05-20 18:00", "2024-05-20 21:00", "Tech Hub, 123 Main St, SF"),
        ("ses-ds-1", "act-ds-workshop",
         "Session 1 - Data Wrangling",
         "Introduction to pandas DataFrames and data cleaning",
         "2024-06-01 10:00", "2024-06-01 14:00", "Online via Zoom"),
        ("ses-ds-2", "act-ds-workshop",
         "Session 2 - Visualisation",
         "matplotlib, seaborn, and plotly for data storytelling",
         "2024-06-08 10:00", "2024-06-08 14:00", "Online via Zoom"),
        ("ses-ds-3", "act-ds-workshop",
         "Session 3 - Intro to ML",
         "scikit-learn: regression, classification, evaluation",
         "2024-06-15 10:00", "2024-06-15 14:00", "Online via Zoom"),
    ]
    for sid, act_id, title, desc, start, end, loc in ses_rows:
        try:
            await env.DB.prepare(
                "INSERT INTO sessions "
                "(id,activity_id,title,description,start_time,end_time,location)"
                " VALUES (?,?,?,?,?,?,?)"
            ).bind(
                sid, act_id, title,
                encrypt(desc, enc_key),
                start, end,
                encrypt(loc, enc_key),
            ).run()
        except Exception:
            pass

    # ---- enrollments ---------------------------------------------------------
    enr_rows = [
        ("enr-c-py",     "act-py-begin",    cid, "participant"),
        ("enr-c-js",     "act-js-meetup",   cid, "participant"),
        ("enr-c-ds",     "act-ds-workshop", cid, "participant"),
        ("enr-d-py",     "act-py-begin",    did, "participant"),
        ("enr-d-webdev", "act-webdev",      did, "participant"),
        ("enr-b-py",     "act-py-begin",    bid, "instructor"),
    ]
    for eid, act_id, uid, role in enr_rows:
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO enrollments (id,activity_id,user_id,role)"
                " VALUES (?,?,?,?)"
            ).bind(eid, act_id, uid, role).run()
        except Exception:
            pass
