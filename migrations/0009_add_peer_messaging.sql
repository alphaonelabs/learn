-- Migration 0009: Peer connections, peer messages, and secure messages

CREATE TABLE IF NOT EXISTS peer_connections (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (sender_id <> receiver_id),
    UNIQUE (sender_id, receiver_id),
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pc_sender   ON peer_connections(sender_id);
CREATE INDEX IF NOT EXISTS idx_pc_receiver ON peer_connections(receiver_id);
CREATE INDEX IF NOT EXISTS idx_pc_status   ON peer_connections(status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pc_pair_unique
    ON peer_connections (
        CASE WHEN sender_id < receiver_id THEN sender_id ELSE receiver_id END,
        CASE WHEN sender_id < receiver_id THEN receiver_id ELSE sender_id END
    );

CREATE TABLE IF NOT EXISTS peer_messages (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content_enc TEXT NOT NULL,
    is_read     INTEGER NOT NULL DEFAULT 0,
    read_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pm_sender   ON peer_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_pm_receiver ON peer_messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_pm_thread   ON peer_messages(sender_id, receiver_id);

CREATE TABLE IF NOT EXISTS secure_messages (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content_enc TEXT NOT NULL,
    is_starred  INTEGER NOT NULL DEFAULT 0,
    is_read     INTEGER NOT NULL DEFAULT 0,
    read_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sm_receiver ON secure_messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_sm_sender   ON secure_messages(sender_id);
