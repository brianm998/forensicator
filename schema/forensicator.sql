-- forensicator catalog schema
-- This file is the canonical source of truth for the SQLite schema used by
-- all three implementations (perl, python, c++).
--
-- schema_version is stored in the meta table; bumps require a coordinated
-- update across implementations and a migration step.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS volumes (
  volume_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname    TEXT NOT NULL,
  volume      TEXT NOT NULL,
  mount_point TEXT,
  os          TEXT,
  scanned_at  INTEGER,
  UNIQUE(hostname, volume)
);

CREATE TABLE IF NOT EXISTS files (
  file_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  volume_id  INTEGER NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  path_norm  TEXT NOT NULL,
  size       INTEGER NOT NULL,
  mtime      INTEGER NOT NULL,
  sha512     TEXT,
  scanned_at INTEGER NOT NULL,
  UNIQUE(volume_id, path_norm)
);

CREATE INDEX IF NOT EXISTS idx_files_sha512        ON files(sha512) WHERE sha512 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_files_size          ON files(size);
CREATE INDEX IF NOT EXISTS idx_files_volume_path   ON files(volume_id, path_norm);
