-- Migration 0006: Add course_materials table for activity file attachments

CREATE TABLE IF NOT EXISTS course_materials (
    id          TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    file_key    TEXT NOT NULL,
    uploaded_by TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_materials_activity ON course_materials(activity_id);
CREATE INDEX IF NOT EXISTS idx_materials_uploader ON course_materials(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_materials_created  ON course_materials(activity_id, created_at DESC);
