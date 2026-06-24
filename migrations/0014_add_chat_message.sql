-- Migration: 0014_add_chat_message
-- Adds the chat_message table used by ChatDO for encrypted message persistence.
-- Content is encrypted with AES-256-GCM before storage (via ChatDO._persist_message).

CREATE TABLE IF NOT EXISTS chat_message (
    id           TEXT PRIMARY KEY,
    classroom_id TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    display_name TEXT,
    content      TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_classroom ON chat_message(classroom_id);
CREATE INDEX IF NOT EXISTS idx_chat_created   ON chat_message(classroom_id, created_at);
