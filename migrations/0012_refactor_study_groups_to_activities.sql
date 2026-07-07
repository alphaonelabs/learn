-- Migration 0012: Refactor study groups to be keyed by activities.id
-- Add study-group-related columns to the central activities model.
ALTER TABLE activities ADD COLUMN max_members INTEGER;
ALTER TABLE activities ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0;
ALTER TABLE activities ADD COLUMN updated_at TEXT;

UPDATE activities
SET description = (
    SELECT COALESCE(activities.description, sg.description)
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
);

-- Ensure host_id reflects the study group creator_id.
UPDATE activities
SET host_id = (
    SELECT sg.creator_id
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
);

-- Preserve created_at from study_groups for corresponding activities.
UPDATE activities
SET created_at = (
    SELECT sg.created_at
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
);

-- Migrate updated_at into the new activities.updated_at column.
UPDATE activities
SET updated_at = (
    SELECT sg.updated_at
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
          AND updated_at IS NOT NULL
);

-- Migrate max_members and is_private into activities.
UPDATE activities
SET max_members = (
    SELECT sg.max_members
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
          AND max_members IS NOT NULL
);

UPDATE activities
SET is_private = (
    SELECT sg.is_private
    FROM study_groups sg
    WHERE sg.activity_id = activities.id
)
WHERE id IN (
    SELECT DISTINCT activity_id FROM study_groups WHERE activity_id IS NOT NULL
);

-- 1) Create new membership table keyed by activities.id
CREATE TABLE IF NOT EXISTS study_group_members_new (
    id          TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',
    joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (activity_id, user_id),
    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)     REFERENCES users(id)     ON DELETE CASCADE
);

-- 2) Copy existing membership rows by following study_groups.activity_id
INSERT INTO study_group_members_new (id, activity_id, user_id, role, joined_at)
SELECT sm.id, sg.activity_id, sm.user_id, sm.role, sm.joined_at
FROM study_group_members sm
JOIN study_groups sg ON sg.id = sm.group_id
WHERE sg.activity_id IS NOT NULL;

-- 3) Replace old membership table
DROP TABLE study_group_members;
ALTER TABLE study_group_members_new RENAME TO study_group_members;

-- 4) Create new invites table keyed by activities.id
CREATE TABLE IF NOT EXISTS study_group_invites_new (
    id          TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL,
    inviter_id  TEXT NOT NULL,
    invitee_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (activity_id, invitee_id),
    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    FOREIGN KEY (inviter_id)  REFERENCES users(id)     ON DELETE CASCADE,
    FOREIGN KEY (invitee_id)  REFERENCES users(id)     ON DELETE CASCADE
);

-- 5) Copy existing invite rows by following study_groups.activity_id
INSERT INTO study_group_invites_new (id, activity_id, inviter_id, invitee_id, status, created_at, updated_at)
SELECT i.id, sg.activity_id, i.inviter_id, i.invitee_id, i.status, i.created_at, i.updated_at
FROM study_group_invites i
JOIN study_groups sg ON sg.id = i.group_id
WHERE sg.activity_id IS NOT NULL;

-- 6) Replace old invites table
DROP TABLE study_group_invites;
ALTER TABLE study_group_invites_new RENAME TO study_group_invites;

-- 7) Drop obsolete study_groups table and its indexes
DROP TABLE study_groups;

-- 8) Recreate supporting indexes to match updated schema
CREATE INDEX IF NOT EXISTS idx_sgm_activity        ON study_group_members(activity_id);
CREATE INDEX IF NOT EXISTS idx_sgm_user            ON study_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_sgi_activity        ON study_group_invites(activity_id);
CREATE INDEX IF NOT EXISTS idx_sgi_invitee_status  ON study_group_invites(invitee_id, status);

