-- Credentials, encrypted at rest.
--
-- The primary key is (tenant_id, id), not id alone: tenant scoping is a
-- property of the schema rather than of every query remembering to filter.
CREATE TABLE IF NOT EXISTS credentials (
  tenant_id         TEXT    NOT NULL,
  id                TEXT    NOT NULL,
  label             TEXT    NOT NULL,
  -- Masked for display. The full CPF lives inside the sealed blob.
  cpf_masked        TEXT    NOT NULL,
  -- Stored rather than derived so listing never has to unseal anything.
  has_totp          INTEGER NOT NULL,
  status            TEXT    NOT NULL,
  sealed_ciphertext TEXT    NOT NULL,
  sealed_iv         TEXT    NOT NULL,
  last_login_at     INTEGER,
  last_error        TEXT,
  PRIMARY KEY (tenant_id, id)
);

-- API keys, stored only as SHA-256 hashes.
--
-- A leaked database must not yield usable keys, so the plaintext is never
-- written; lookup hashes the presented key and compares.
CREATE TABLE IF NOT EXISTS api_keys (
  key_hash   TEXT PRIMARY KEY,
  tenant_id  TEXT    NOT NULL,
  label      TEXT    NOT NULL,
  revoked_at INTEGER
);

-- Append-only record of every credential use.
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT    NOT NULL,
  credential_id TEXT    NOT NULL,
  event         TEXT    NOT NULL,
  detail        TEXT,
  at            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_by_credential
  ON audit_log (tenant_id, credential_id, at DESC);
