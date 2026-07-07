-- Migration 0012: Add study-group support to the activities-based schema
-- This branch never had a separate study_groups table in migrations, so this
-- migration only extends activities and creates the study-group tables
-- keyed by activities.id.

-- Add study-group related columns to the central activities model.
ALTER TABLE activities ADD COLUMN max_members INTEGER;
ALTER TABLE activities ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0;
ALTER TABLE activities ADD COLUMN updated_at TEXT;

-- Create study group memberships & invites tables (keyed by activities.id).
CREATE TABLE IF NOT EXISTS study_group_members (
    id          TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',
    joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (activity_id, user_id),
    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)     REFERENCES users(id)     ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS study_group_invites (
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

-- Supporting indexes to match the updated schema.
CREATE INDEX IF NOT EXISTS idx_sgm_activity        ON study_group_members(activity_id);
CREATE INDEX IF NOT EXISTS idx_sgm_user            ON study_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_sgi_activity        ON study_group_invites(activity_id);
CREATE INDEX IF NOT EXISTS idx_sgi_invitee_status  ON study_group_invites(invitee_id, status);
