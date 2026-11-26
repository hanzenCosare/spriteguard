-- SpriteGuard Neon Postgres + pgvector schema

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS pr_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_full_name TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  head_sha TEXT NOT NULL,
  head_ref TEXT NOT NULL,
  head_repo_full_name TEXT NOT NULL,
  base_ref TEXT NOT NULL,
  pr_title TEXT NOT NULL,
  pr_author TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  risk_score INTEGER,
  severity TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  secrets_count INTEGER NOT NULL DEFAULT 0,
  flagged_egress_count INTEGER NOT NULL DEFAULT 0,
  egress_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  sprite_name TEXT,
  sprite_state TEXT NOT NULL DEFAULT 'none',
  checkpoint_id TEXT,
  report_markdown TEXT,
  report_json JSONB,
  comment_id BIGINT,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pr_scans_repo_pr_created
  ON pr_scans (repo_full_name, pr_number, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pr_scans_repo_pr_sha
  ON pr_scans (repo_full_name, pr_number, head_sha);

CREATE INDEX IF NOT EXISTS idx_pr_scans_sprite_name
  ON pr_scans (sprite_name);

CREATE INDEX IF NOT EXISTS idx_pr_scans_status
  ON pr_scans (status);

CREATE TABLE IF NOT EXISTS security_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES pr_scans(id) ON DELETE CASCADE,
  repo_full_name TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  finding_id TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0.8,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL DEFAULT 0,
  evidence TEXT NOT NULL,
  exploitability TEXT NOT NULL,
  runtime_proof TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL,
  source TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  embedding vector(1024) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_findings_scan
  ON security_findings (scan_id);

CREATE INDEX IF NOT EXISTS idx_security_findings_repo_created
  ON security_findings (repo_full_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_findings_embedding
  ON security_findings USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS audit_patches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL UNIQUE REFERENCES pr_scans(id) ON DELETE CASCADE,
  summary TEXT NOT NULL,
  files_json JSONB NOT NULL,
  diff TEXT NOT NULL,
  diff_sha256 TEXT NOT NULL,
  verification_json JSONB,
  post_merge_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
  generator TEXT NOT NULL,
  status TEXT NOT NULL,
  approved_by TEXT,
  commit_sha TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMPTZ,
  pushed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audit_patches_scan
  ON audit_patches (scan_id);

CREATE INDEX IF NOT EXISTS idx_audit_patches_status
  ON audit_patches (status);
