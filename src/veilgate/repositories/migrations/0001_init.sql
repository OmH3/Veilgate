PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS sessions (
  session_id     TEXT PRIMARY KEY,
  label          TEXT,
  transport      TEXT NOT NULL,
  integrity      TEXT NOT NULL DEFAULT 'HIGH' CHECK (integrity IN ('HIGH','LOW')),
  created_at     TEXT NOT NULL,
  last_seen_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token_id              TEXT NOT NULL,
  session_id            TEXT NOT NULL REFERENCES sessions(session_id),
  rendered              TEXT NOT NULL,
  token_type            TEXT NOT NULL,
  sensitivity           TEXT NOT NULL,
  value_kind            TEXT NOT NULL,
  value_hmac            BLOB NOT NULL,
  ciphertext            BLOB NOT NULL,
  nonce                 BLOB NOT NULL,
  origin_ref            TEXT NOT NULL,
  origin_path           TEXT NOT NULL,
  origin_event_id       TEXT NOT NULL,
  allowed_sinks_json    TEXT NOT NULL,
  allow_external_egress INTEGER NOT NULL,
  created_at            TEXT NOT NULL,
  expires_at            TEXT NOT NULL,
  PRIMARY KEY (session_id, token_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tokens_value ON tokens(session_id, token_type, value_hmac);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tokens_rendered ON tokens(session_id, rendered);
CREATE INDEX IF NOT EXISTS ix_tokens_expiry ON tokens(expires_at);

CREATE TABLE IF NOT EXISTS tool_catalog (
  qualified_ref   TEXT PRIMARY KEY,
  server_id       TEXT NOT NULL,
  fingerprint     TEXT NOT NULL,
  pinned_fp       TEXT,
  status          TEXT NOT NULL CHECK (status IN ('active','quarantined','denied')),
  capabilities    TEXT NOT NULL,
  is_open_world   INTEGER NOT NULL DEFAULT 0,
  untrusted_tool  INTEGER NOT NULL DEFAULT 0,
  risk_level      TEXT NOT NULL,
  schema_tokens   INTEGER NOT NULL,
  raw_json        TEXT NOT NULL,
  first_seen_at   TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_catalog_server ON tool_catalog(server_id);

CREATE TABLE IF NOT EXISTS schema_cache (
  qualified_ref      TEXT NOT NULL,
  shape_fingerprint  TEXT NOT NULL,
  classifications    TEXT NOT NULL,
  source             TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  PRIMARY KEY (qualified_ref, shape_fingerprint)
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id       TEXT NOT NULL UNIQUE,
  ts             TEXT NOT NULL,
  session_id     TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  kind           TEXT NOT NULL,
  qualified_ref  TEXT,
  reason         TEXT,
  details_json   TEXT NOT NULL,
  prev_hash      TEXT NOT NULL,
  row_hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_session_ts ON audit_events(session_id, ts);
CREATE INDEX IF NOT EXISTS ix_audit_kind_ts ON audit_events(kind, ts);

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_events BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_events BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TABLE IF NOT EXISTS approvals (
  approval_id    TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL,
  qualified_ref  TEXT NOT NULL,
  summary_json   TEXT NOT NULL,
  reason         TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','APPROVED_AND_SAVED','DENIED','EXPIRED')),
  learned_grant  TEXT,
  requested_at   TEXT NOT NULL,
  decided_at     TEXT,
  decided_by     TEXT
);
CREATE INDEX IF NOT EXISTS ix_approvals_status ON approvals(status, requested_at);

CREATE TABLE IF NOT EXISTS result_stash (
  stash_id       TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL,
  qualified_ref  TEXT NOT NULL,
  payload_json   TEXT NOT NULL,
  expires_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_stash_expiry ON result_stash(expires_at);

CREATE TABLE IF NOT EXISTS telemetry (
  event_id        TEXT PRIMARY KEY REFERENCES audit_events(event_id),
  tokens_before   INTEGER,
  tokens_after    INTEGER,
  latency_total_ms REAL,
  latency_upstream_ms REAL,
  latency_firewall_ms REAL
);
