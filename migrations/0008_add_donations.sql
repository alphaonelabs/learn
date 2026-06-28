-- Migration 0008: Add donations support

CREATE TABLE IF NOT EXISTS donations (
    id                       TEXT PRIMARY KEY,
    user_id                  TEXT,
    amount                   INTEGER NOT NULL,
    currency                 TEXT NOT NULL DEFAULT 'usd',
    donation_type            TEXT NOT NULL DEFAULT 'one-time',
    donor_name               TEXT,
    donor_email              TEXT,
    message                  TEXT,
    anonymous                INTEGER NOT NULL DEFAULT 0,
    status                   TEXT NOT NULL DEFAULT 'pending',
    stripe_payment_intent_id TEXT,
    stripe_subscription_id   TEXT,
    stripe_customer_id       TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_donations_created_at ON donations(created_at);
CREATE INDEX IF NOT EXISTS idx_donations_status     ON donations(status);
CREATE INDEX IF NOT EXISTS idx_donations_user_id    ON donations(user_id);
