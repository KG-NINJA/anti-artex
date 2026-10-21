-- Dedicated research database only. Never bind a production database.
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  observed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (length(envelope) <= 8192)
);
CREATE INDEX IF NOT EXISTS events_expiry ON events(expires_at);
CREATE INDEX IF NOT EXISTS events_time ON events(observed_at, event_id);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  initialized INTEGER NOT NULL DEFAULT 0 CHECK(initialized IN (0,1)),
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS daily_budget (
  day TEXT PRIMARY KEY,
  requests INTEGER NOT NULL CHECK(requests >= 0)
);
