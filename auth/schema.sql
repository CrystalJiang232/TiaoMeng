CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_login INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_users_active ON users(active) WHERE active = 1;
