import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import pgvector from 'pgvector/pg';
import type { AppConfig } from '../config.js';
import type { Logger } from '../logger.js';
import type {
  DashboardStats,
  EgressDomain,
  NewScanInput,
  PastIncident,
  PatchFile,
  PatchRecord,
  PatchStatus,
  PatchVerification,
  ScanRecord,
  ScanReport,
  ScanStatus,
  Severity,
  SeverityBadge,
  SpriteState,
  StoredFinding,
} from '../types.js';

const { Pool } = pg;

export const EMBEDDING_DIMENSIONS = 1024;

export interface ScanUpdate {
  status?: ScanStatus;
  riskScore?: number | null;
  severity?: SeverityBadge | null;
  findingsCount?: number;
  secretsCount?: number;
  flaggedEgressCount?: number;
  egressDomains?: EgressDomain[];
  spriteName?: string | null;
  spriteState?: SpriteState;
  checkpointId?: string | null;
  reportMarkdown?: string | null;
  report?: ScanReport | null;
  commentId?: number | null;
  error?: string | null;
  completedAt?: string | null;
}

export interface SavePatchInput {
  scanId: string;
  summary: string;
  files: PatchFile[];
  diff: string;
  diffSha256: string;
  verification: PatchVerification | null;
  postMergeActions: string[];
  generator: 'claude' | 'heuristic';
  status: PatchStatus;
}

export interface PatchUpdate {
  status?: PatchStatus;
  verification?: PatchVerification | null;
  approvedBy?: string | null;
  commitSha?: string | null;
  approvedAt?: string | null;
  pushedAt?: string | null;
}

export interface Store {
  readonly backend: 'postgres' | 'memory';
  init(): Promise<void>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
  createScan(input: NewScanInput): Promise<ScanRecord>;
  updateScan(scanId: string, patch: ScanUpdate): Promise<ScanRecord | null>;
  updateSpriteStateByName(spriteName: string, state: SpriteState): Promise<void>;
  supersedePriorScans(repoFullName: string, prNumber: number, keepScanId: string): Promise<ScanRecord[]>;
  getScan(scanId: string): Promise<ScanRecord | null>;
  getLatestScanForPr(repoFullName: string, prNumber: number): Promise<ScanRecord | null>;
  listScans(opts?: { limit?: number; repo?: string; status?: ScanStatus }): Promise<ScanRecord[]>;
  listStaleSprites(olderThanHours: number): Promise<ScanRecord[]>;
  saveFindings(findings: StoredFinding[]): Promise<void>;
  searchSimilarFindings(
    repoFullName: string,
    embedding: number[],
    opts?: { limit?: number; excludeScanId?: string; minSimilarity?: number },
  ): Promise<PastIncident[]>;
  savePatch(patch: SavePatchInput): Promise<PatchRecord>;
  getPatch(scanId: string): Promise<PatchRecord | null>;
  updatePatch(scanId: string, patch: PatchUpdate): Promise<PatchRecord | null>;
  claimPatchApproval(scanId: string, approver: string): Promise<PatchRecord | null>;
  getStats(): Promise<DashboardStats>;
}

/* -------------------------------------------------------------------------------------------------
 * Embeddings (Voyage AI with deterministic L2-normalized local hashing fallback)
 * -----------------------------------------------------------------------------------------------*/

export function cosineSimilarity(a: readonly number[], b: readonly number[]): number {
  const len = Math.min(a.length, b.length);
  if (len === 0) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i++) {
    const va = a[i] ?? 0;
    const vb = b[i] ?? 0;
    dot += va * vb;
    normA += va * va;
    normB += vb * vb;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

export function deterministicEmbedding(text: string, dimensions = EMBEDDING_DIMENSIONS): number[] {
  const vec = new Float64Array(dimensions);
  const tokens = text
    .toLowerCase()
    .replace(/[^a-z0-9_./:-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 600);

  if (tokens.length === 0) {
    vec[0] = 1;
    return Array.from(vec);
  }

  const addFeature = (feature: string, weight: number): void => {
    const digest = createHash('sha256').update(feature).digest();
    const bucket = digest.readUInt32BE(0) % dimensions;
    const sign = (digest[4] ?? 0) % 2 === 0 ? 1 : -1;
    vec[bucket] = (vec[bucket] ?? 0) + sign * weight;
  };

  for (let i = 0; i < tokens.length; i++) {
    const t1 = tokens[i];
    if (!t1) continue;
    addFeature(`1:${t1}`, 1.0);
    const t2 = tokens[i + 1];
    if (t2) addFeature(`2:${t1} ${t2}`, 1.4);
    const t3 = tokens[i + 2];
    if (t3) addFeature(`3:${t1} ${t2} ${t3}`, 1.7);
  }

  let norm = 0;
  for (let i = 0; i < dimensions; i++) {
    const v = vec[i] ?? 0;
    norm += v * v;
  }
  norm = Math.sqrt(norm) || 1;
  const normalized = new Array<number>(dimensions);
  for (let i = 0; i < dimensions; i++) {
    normalized[i] = Math.round(((vec[i] ?? 0) / norm) * 1e6) / 1e6;
  }
  return normalized;
}

export class EmbeddingClient {
  readonly dimensions: number;

  constructor(
    private readonly cfg: AppConfig['embeddings'],
    private readonly log: Logger,
  ) {
    this.dimensions = cfg.dimensions;
  }

  async embed(text: string): Promise<number[]> {
    const [vec] = await this.embedBatch([text]);
    return vec ?? deterministicEmbedding(text, this.dimensions);
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];
    const clipped = texts.map((t) => (t.trim() ? t.slice(0, 8000) : 'empty'));
    if (!this.cfg.voyageApiKey) {
      return clipped.map((t) => deterministicEmbedding(t, this.dimensions));
    }

    try {
      const res = await fetch('https://api.voyageai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.cfg.voyageApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          input: clipped,
          model: this.cfg.voyageModel,
          output_dimension: this.dimensions,
        }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        throw new Error(`Voyage API responded with ${res.status}`);
      }
      const json = (await res.json()) as { data?: Array<{ embedding?: number[]; index?: number }> };
      const rows = (json.data ?? []).sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
      if (rows.length !== clipped.length) {
        throw new Error(`Voyage API returned ${rows.length} embeddings for ${clipped.length} inputs`);
      }
      return rows.map((row, idx) =>
        Array.isArray(row.embedding) && row.embedding.length === this.dimensions
          ? row.embedding
          : deterministicEmbedding(clipped[idx] ?? '', this.dimensions),
      );
    } catch (err) {
      this.log.warn({ err }, 'Voyage embedding failed; falling back to local feature-hash embeddings');
      return clipped.map((t) => deterministicEmbedding(t, this.dimensions));
    }
  }
}

/* -------------------------------------------------------------------------------------------------
 * Neon Postgres + pgvector Store
 * -----------------------------------------------------------------------------------------------*/

interface DbScanRow {
  id: string;
  repo_full_name: string;
  pr_number: number;
  head_sha: string;
  head_ref: string;
  head_repo_full_name: string;
  base_ref: string;
  pr_title: string;
  pr_author: string;
  status: ScanStatus;
  risk_score: number | null;
  severity: SeverityBadge | null;
  findings_count: number;
  secrets_count: number;
  flagged_egress_count: number;
  egress_domains: EgressDomain[] | string | null;
  sprite_name: string | null;
  sprite_state: SpriteState;
  checkpoint_id: string | null;
  report_markdown: string | null;
  report_json: ScanReport | string | null;
  comment_id: string | number | null;
  error: string | null;
  created_at: Date | string;
  updated_at: Date | string;
  completed_at: Date | string | null;
}

interface DbPatchRow {
  scan_id: string;
  summary: string;
  files_json: PatchFile[] | string;
  diff: string;
  diff_sha256: string;
  verification_json: PatchVerification | string | null;
  post_merge_actions: string[] | string | null;
  generator: 'claude' | 'heuristic';
  status: PatchStatus;
  approved_by: string | null;
  commit_sha: string | null;
  created_at: Date | string;
  approved_at: Date | string | null;
  pushed_at: Date | string | null;
}

function toIso(val: Date | string | null | undefined): string | null {
  if (val === null || val === undefined) return null;
  return val instanceof Date ? val.toISOString() : new Date(val).toISOString();
}

function parseJsonField<T>(val: T | string | null | undefined, fallback: T): T {
  if (val === null || val === undefined) return fallback;
  if (typeof val === 'string') {
    try {
      return JSON.parse(val) as T;
    } catch {
      return fallback;
    }
  }
  return val;
}

function mapScanRow(row: DbScanRow): ScanRecord {
  return {
    id: row.id,
    repoFullName: row.repo_full_name,
    prNumber: Number(row.pr_number),
    headSha: row.head_sha,
    headRef: row.head_ref,
    headRepoFullName: row.head_repo_full_name,
    baseRef: row.base_ref,
    prTitle: row.pr_title,
    prAuthor: row.pr_author,
    status: row.status,
    riskScore: row.risk_score === null ? null : Number(row.risk_score),
    severity: row.severity,
    findingsCount: Number(row.findings_count),
    secretsCount: Number(row.secrets_count),
    flaggedEgressCount: Number(row.flagged_egress_count),
    egressDomains: parseJsonField<EgressDomain[]>(row.egress_domains, []),
    spriteName: row.sprite_name,
    spriteState: row.sprite_state,
    checkpointId: row.checkpoint_id,
    reportMarkdown: row.report_markdown,
    report: parseJsonField<ScanReport | null>(row.report_json, null),
    commentId: row.comment_id === null || row.comment_id === undefined ? null : Number(row.comment_id),
    error: row.error,
    createdAt: toIso(row.created_at) ?? new Date().toISOString(),
    updatedAt: toIso(row.updated_at) ?? new Date().toISOString(),
    completedAt: toIso(row.completed_at),
  };
}

function mapPatchRow(row: DbPatchRow): PatchRecord {
  return {
    scanId: row.scan_id,
    summary: row.summary,
    files: parseJsonField<PatchFile[]>(row.files_json, []),
    diff: row.diff,
    diffSha256: row.diff_sha256,
    verification: parseJsonField<PatchVerification | null>(row.verification_json, null),
    postMergeActions: parseJsonField<string[]>(row.post_merge_actions, []),
    generator: row.generator,
    status: row.status,
    approvedBy: row.approved_by,
    commitSha: row.commit_sha,
    createdAt: toIso(row.created_at) ?? new Date().toISOString(),
    approvedAt: toIso(row.approved_at),
    pushedAt: toIso(row.pushed_at),
  };
}

export class PostgresStore implements Store {
  readonly backend = 'postgres' as const;
  private readonly pool: pg.Pool;

  constructor(
    connectionString: string,
    ssl: boolean,
    private readonly log: Logger,
  ) {
    this.pool = new Pool({
      connectionString,
      ssl: ssl ? { rejectUnauthorized: false } : undefined,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000,
    });
    this.pool.on('error', (err) => {
      this.log.error({ err }, 'Postgres pool background error');
    });
  }

  async init(): Promise<void> {
    const schemaPath = fileURLToPath(new URL('./schema.sql', import.meta.url));
    const sql = await readFile(schemaPath, 'utf8');
    const client = await this.pool.connect();
    try {
      await client.query(sql);
      await pgvector.registerTypes(client);
      this.log.info('Neon Postgres + pgvector schema initialized');
    } finally {
      client.release();
    }
  }

  async ping(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async createScan(input: NewScanInput): Promise<ScanRecord> {
    const { rows } = await this.pool.query<DbScanRow>(
      `INSERT INTO pr_scans (
        repo_full_name, pr_number, head_sha, head_ref, head_repo_full_name, base_ref, pr_title, pr_author, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'queued')
      RETURNING *`,
      [
        input.repoFullName,
        input.prNumber,
        input.headSha,
        input.headRef,
        input.headRepoFullName,
        input.baseRef,
        input.prTitle,
        input.prAuthor,
      ],
    );
    const row = rows[0];
    if (!row) throw new Error('failed to insert pr_scans row');
    return mapScanRow(row);
  }

  async updateScan(scanId: string, patch: ScanUpdate): Promise<ScanRecord | null> {
    const sets: string[] = ['updated_at = NOW()'];
    const values: unknown[] = [];

    const push = (column: string, value: unknown): void => {
      values.push(value);
      sets.push(`${column} = $${values.length}`);
    };

    if (patch.status !== undefined) push('status', patch.status);
    if (patch.riskScore !== undefined) push('risk_score', patch.riskScore);
    if (patch.severity !== undefined) push('severity', patch.severity);
    if (patch.findingsCount !== undefined) push('findings_count', patch.findingsCount);
    if (patch.secretsCount !== undefined) push('secrets_count', patch.secretsCount);
    if (patch.flaggedEgressCount !== undefined) push('flagged_egress_count', patch.flaggedEgressCount);
    if (patch.egressDomains !== undefined) push('egress_domains', JSON.stringify(patch.egressDomains));
    if (patch.spriteName !== undefined) push('sprite_name', patch.spriteName);
    if (patch.spriteState !== undefined) push('sprite_state', patch.spriteState);
    if (patch.checkpointId !== undefined) push('checkpoint_id', patch.checkpointId);
    if (patch.reportMarkdown !== undefined) push('report_markdown', patch.reportMarkdown);
    if (patch.report !== undefined) push('report_json', patch.report === null ? null : JSON.stringify(patch.report));
    if (patch.commentId !== undefined) push('comment_id', patch.commentId);
    if (patch.error !== undefined) push('error', patch.error);
    if (patch.completedAt !== undefined) push('completed_at', patch.completedAt);

    values.push(scanId);
    const { rows } = await this.pool.query<DbScanRow>(
      `UPDATE pr_scans SET ${sets.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values,
    );
    return rows[0] ? mapScanRow(rows[0]) : null;
  }

  async updateSpriteStateByName(spriteName: string, state: SpriteState): Promise<void> {
    await this.pool.query(
      `UPDATE pr_scans SET sprite_state = $1, updated_at = NOW() WHERE sprite_name = $2`,
      [state, spriteName],
    );
  }

  async supersedePriorScans(repoFullName: string, prNumber: number, keepScanId: string): Promise<ScanRecord[]> {
    const { rows } = await this.pool.query<DbScanRow>(
      `UPDATE pr_scans
       SET status = 'superseded', updated_at = NOW()
       WHERE repo_full_name = $1
         AND pr_number = $2
         AND id <> $3
         AND status IN ('queued', 'running', 'awaiting_approval', 'needs_review')
       RETURNING *`,
      [repoFullName, prNumber, keepScanId],
    );
    return rows.map(mapScanRow);
  }

  async getScan(scanId: string): Promise<ScanRecord | null> {
    const { rows } = await this.pool.query<DbScanRow>(`SELECT * FROM pr_scans WHERE id = $1`, [scanId]);
    return rows[0] ? mapScanRow(rows[0]) : null;
  }

  async getLatestScanForPr(repoFullName: string, prNumber: number): Promise<ScanRecord | null> {
    const { rows } = await this.pool.query<DbScanRow>(
      `SELECT * FROM pr_scans
       WHERE repo_full_name = $1 AND pr_number = $2 AND status <> 'superseded'
       ORDER BY created_at DESC
       LIMIT 1`,
      [repoFullName, prNumber],
    );
    if (rows[0]) return mapScanRow(rows[0]);
    const fallback = await this.pool.query<DbScanRow>(
      `SELECT * FROM pr_scans
       WHERE repo_full_name = $1 AND pr_number = $2
       ORDER BY created_at DESC
       LIMIT 1`,
      [repoFullName, prNumber],
    );
    return fallback.rows[0] ? mapScanRow(fallback.rows[0]) : null;
  }

  async listScans(opts: { limit?: number; repo?: string; status?: ScanStatus } = {}): Promise<ScanRecord[]> {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    const clauses: string[] = [];
    const values: unknown[] = [];

    if (opts.repo) {
      values.push(opts.repo);
      clauses.push(`repo_full_name = $${values.length}`);
    }
    if (opts.status) {
      values.push(opts.status);
      clauses.push(`status = $${values.length}`);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    values.push(limit);
    const { rows } = await this.pool.query<DbScanRow>(
      `SELECT * FROM pr_scans ${where} ORDER BY created_at DESC LIMIT $${values.length}`,
      values,
    );
    return rows.map(mapScanRow);
  }

  async listStaleSprites(olderThanHours: number): Promise<ScanRecord[]> {
    const { rows } = await this.pool.query<DbScanRow>(
      `SELECT * FROM pr_scans
       WHERE sprite_name IS NOT NULL
         AND sprite_state IN ('creating', 'running', 'sleeping')
         AND updated_at < NOW() - ($1::integer * INTERVAL '1 hour')`,
      [olderThanHours],
    );
    return rows.map(mapScanRow);
  }

  async saveFindings(findings: StoredFinding[]): Promise<void> {
    if (findings.length === 0) return;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const item of findings) {
        const f = item.finding;
        await client.query(
          `INSERT INTO security_findings (
            scan_id, repo_full_name, pr_number, finding_id, title, category, severity, confidence,
            file_path, line_number, evidence, exploitability, runtime_proof, remediation,
            source, fingerprint, embedding
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::vector)`,
          [
            item.scanId,
            item.repoFullName,
            item.prNumber,
            f.id,
            f.title,
            f.category,
            f.severity,
            f.confidence,
            f.file,
            Math.max(0, Math.trunc(f.line)),
            f.evidence,
            f.exploitability,
            f.runtimeProof,
            f.remediation,
            f.source,
            item.fingerprint,
            pgvector.toSql(item.embedding),
          ],
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async searchSimilarFindings(
    repoFullName: string,
    embedding: number[],
    opts: { limit?: number; excludeScanId?: string; minSimilarity?: number } = {},
  ): Promise<PastIncident[]> {
    const limit = opts.limit ?? 5;
    const minSimilarity = opts.minSimilarity ?? 0.35;
    const vecSql = pgvector.toSql(embedding);

    const params: unknown[] = [repoFullName, vecSql, minSimilarity, limit];
    const excludeClause = opts.excludeScanId ? `AND scan_id <> $5` : '';
    if (opts.excludeScanId) params.push(opts.excludeScanId);

    const { rows } = await this.pool.query<{
      scan_id: string;
      pr_number: number;
      title: string;
      category: string;
      severity: Severity;
      file_path: string;
      exploitability: string;
      similarity: number;
      created_at: Date | string;
    }>(
      `SELECT
         scan_id,
         pr_number,
         title,
         category,
         severity,
         file_path,
         exploitability,
         1 - (embedding <=> $2::vector) AS similarity,
         created_at
       FROM security_findings
       WHERE repo_full_name = $1
         ${excludeClause}
         AND 1 - (embedding <=> $2::vector) >= $3
       ORDER BY embedding <=> $2::vector ASC
       LIMIT $4`,
      params,
    );

    return rows.map((r) => ({
      scanId: r.scan_id,
      prNumber: Number(r.pr_number),
      title: r.title,
      category: r.category,
      severity: r.severity,
      filePath: r.file_path,
      description: r.exploitability,
      similarity: Math.round(Number(r.similarity) * 1000) / 1000,
      createdAt: toIso(r.created_at) ?? new Date().toISOString(),
    }));
  }

  async savePatch(patch: SavePatchInput): Promise<PatchRecord> {
    const { rows } = await this.pool.query<DbPatchRow>(
      `INSERT INTO audit_patches (
        scan_id, summary, files_json, diff, diff_sha256, verification_json, post_merge_actions, generator, status
      ) VALUES ($1, $2, $3::jsonb, $4, $5, $6::jsonb, $7::jsonb, $8, $9)
      ON CONFLICT (scan_id) DO UPDATE SET
        summary = EXCLUDED.summary,
        files_json = EXCLUDED.files_json,
        diff = EXCLUDED.diff,
        diff_sha256 = EXCLUDED.diff_sha256,
        verification_json = EXCLUDED.verification_json,
        post_merge_actions = EXCLUDED.post_merge_actions,
        generator = EXCLUDED.generator,
        status = EXCLUDED.status
      RETURNING *`,
      [
        patch.scanId,
        patch.summary,
        JSON.stringify(patch.files),
        patch.diff,
        patch.diffSha256,
        patch.verification === null ? null : JSON.stringify(patch.verification),
        JSON.stringify(patch.postMergeActions),
        patch.generator,
        patch.status,
      ],
    );
    const row = rows[0];
    if (!row) throw new Error('failed to upsert audit_patches row');
    return mapPatchRow(row);
  }

  async getPatch(scanId: string): Promise<PatchRecord | null> {
    const { rows } = await this.pool.query<DbPatchRow>(`SELECT * FROM audit_patches WHERE scan_id = $1`, [scanId]);
    return rows[0] ? mapPatchRow(rows[0]) : null;
  }

  async updatePatch(scanId: string, patch: PatchUpdate): Promise<PatchRecord | null> {
    const sets: string[] = [];
    const values: unknown[] = [];

    const push = (col: string, val: unknown): void => {
      values.push(val);
      sets.push(`${col} = $${values.length}`);
    };

    if (patch.status !== undefined) push('status', patch.status);
    if (patch.verification !== undefined) {
      push('verification_json', patch.verification === null ? null : JSON.stringify(patch.verification));
    }
    if (patch.approvedBy !== undefined) push('approved_by', patch.approvedBy);
    if (patch.commitSha !== undefined) push('commit_sha', patch.commitSha);
    if (patch.approvedAt !== undefined) push('approved_at', patch.approvedAt);
    if (patch.pushedAt !== undefined) push('pushed_at', patch.pushedAt);

    if (sets.length === 0) return this.getPatch(scanId);
    values.push(scanId);
    const { rows } = await this.pool.query<DbPatchRow>(
      `UPDATE audit_patches SET ${sets.join(', ')} WHERE scan_id = $${values.length} RETURNING *`,
      values,
    );
    return rows[0] ? mapPatchRow(rows[0]) : null;
  }

  async claimPatchApproval(scanId: string, approver: string): Promise<PatchRecord | null> {
    const { rows } = await this.pool.query<DbPatchRow>(
      `UPDATE audit_patches
       SET status = 'approved', approved_by = $2, approved_at = NOW()
       WHERE scan_id = $1 AND status IN ('verified', 'verified_with_warnings')
       RETURNING *`,
      [scanId, approver],
    );
    return rows[0] ? mapPatchRow(rows[0]) : null;
  }

  async getStats(): Promise<DashboardStats> {
    const { rows } = await this.pool.query<{
      prs_audited: string;
      secrets_blocked: string;
      avg_risk: string | null;
      active_sprites: string;
      sleeping_sprites: string;
      patches_pushed: string;
      awaiting_approval: string;
    }>(`
      SELECT
        COUNT(*) FILTER (WHERE status NOT IN ('queued', 'running', 'superseded')) AS prs_audited,
        COALESCE(SUM(secrets_count) FILTER (WHERE status <> 'superseded'), 0) AS secrets_blocked,
        COALESCE(ROUND(AVG(risk_score) FILTER (WHERE risk_score IS NOT NULL AND status <> 'superseded')), 0) AS avg_risk,
        COUNT(*) FILTER (WHERE sprite_state IN ('creating', 'running')) AS active_sprites,
        COUNT(*) FILTER (WHERE sprite_state = 'sleeping') AS sleeping_sprites,
        COUNT(*) FILTER (WHERE status = 'pushed') AS patches_pushed,
        COUNT(*) FILTER (WHERE status = 'awaiting_approval') AS awaiting_approval
      FROM pr_scans
    `);
    const r = rows[0];
    return {
      prsAudited: Number(r?.prs_audited ?? 0),
      secretsBlocked: Number(r?.secrets_blocked ?? 0),
      averageRiskScore: Number(r?.avg_risk ?? 0),
      activeSprites: Number(r?.active_sprites ?? 0),
      sleepingSprites: Number(r?.sleeping_sprites ?? 0),
      patchesPushed: Number(r?.patches_pushed ?? 0),
      awaitingApproval: Number(r?.awaiting_approval ?? 0),
    };
  }
}

/* -------------------------------------------------------------------------------------------------
 * In-Memory Store — zero-dependency LOCAL_SANDBOX_MODE fallback
 * -----------------------------------------------------------------------------------------------*/

export class InMemoryStore implements Store {
  readonly backend = 'memory' as const;
  private readonly scans = new Map<string, ScanRecord>();
  private readonly patches = new Map<string, PatchRecord>();
  private readonly findings: Array<StoredFinding & { id: string; createdAt: string }> = [];

  async init(): Promise<void> {
    /* nothing to initialize */
  }

  async ping(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    /* no-op */
  }

  async createScan(input: NewScanInput): Promise<ScanRecord> {
    const now = new Date().toISOString();
    const record: ScanRecord = {
      id: randomUUID(),
      repoFullName: input.repoFullName,
      prNumber: input.prNumber,
      headSha: input.headSha,
      headRef: input.headRef,
      headRepoFullName: input.headRepoFullName,
      baseRef: input.baseRef,
      prTitle: input.prTitle,
      prAuthor: input.prAuthor,
      status: 'queued',
      riskScore: null,
      severity: null,
      findingsCount: 0,
      secretsCount: 0,
      flaggedEgressCount: 0,
      egressDomains: [],
      spriteName: null,
      spriteState: 'none',
      checkpointId: null,
      reportMarkdown: null,
      report: null,
      commentId: null,
      error: null,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
    };
    this.scans.set(record.id, record);
    return structuredClone(record);
  }

  async updateScan(scanId: string, patch: ScanUpdate): Promise<ScanRecord | null> {
    const cur = this.scans.get(scanId);
    if (!cur) return null;
    Object.assign(cur, {
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      ...(patch.riskScore !== undefined ? { riskScore: patch.riskScore } : {}),
      ...(patch.severity !== undefined ? { severity: patch.severity } : {}),
      ...(patch.findingsCount !== undefined ? { findingsCount: patch.findingsCount } : {}),
      ...(patch.secretsCount !== undefined ? { secretsCount: patch.secretsCount } : {}),
      ...(patch.flaggedEgressCount !== undefined ? { flaggedEgressCount: patch.flaggedEgressCount } : {}),
      ...(patch.egressDomains !== undefined ? { egressDomains: structuredClone(patch.egressDomains) } : {}),
      ...(patch.spriteName !== undefined ? { spriteName: patch.spriteName } : {}),
      ...(patch.spriteState !== undefined ? { spriteState: patch.spriteState } : {}),
      ...(patch.checkpointId !== undefined ? { checkpointId: patch.checkpointId } : {}),
      ...(patch.reportMarkdown !== undefined ? { reportMarkdown: patch.reportMarkdown } : {}),
      ...(patch.report !== undefined ? { report: structuredClone(patch.report) } : {}),
      ...(patch.commentId !== undefined ? { commentId: patch.commentId } : {}),
      ...(patch.error !== undefined ? { error: patch.error } : {}),
      ...(patch.completedAt !== undefined ? { completedAt: patch.completedAt } : {}),
      updatedAt: new Date().toISOString(),
    });
    return structuredClone(cur);
  }

  async updateSpriteStateByName(spriteName: string, state: SpriteState): Promise<void> {
    const now = new Date().toISOString();
    for (const scan of this.scans.values()) {
      if (scan.spriteName === spriteName) {
        scan.spriteState = state;
        scan.updatedAt = now;
      }
    }
  }

  async supersedePriorScans(repoFullName: string, prNumber: number, keepScanId: string): Promise<ScanRecord[]> {
    const superseded: ScanRecord[] = [];
    const active = new Set<ScanStatus>(['queued', 'running', 'awaiting_approval', 'needs_review']);
    const now = new Date().toISOString();
    for (const scan of this.scans.values()) {
      if (
        scan.repoFullName === repoFullName &&
        scan.prNumber === prNumber &&
        scan.id !== keepScanId &&
        active.has(scan.status)
      ) {
        scan.status = 'superseded';
        scan.updatedAt = now;
        superseded.push(structuredClone(scan));
      }
    }
    return superseded;
  }

  async getScan(scanId: string): Promise<ScanRecord | null> {
    const s = this.scans.get(scanId);
    return s ? structuredClone(s) : null;
  }

  async getLatestScanForPr(repoFullName: string, prNumber: number): Promise<ScanRecord | null> {
    const matches = [...this.scans.values()]
      .filter((s) => s.repoFullName === repoFullName && s.prNumber === prNumber)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const preferred = matches.find((s) => s.status !== 'superseded') ?? matches[0];
    return preferred ? structuredClone(preferred) : null;
  }

  async listScans(opts: { limit?: number; repo?: string; status?: ScanStatus } = {}): Promise<ScanRecord[]> {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    return [...this.scans.values()]
      .filter((s) => (!opts.repo || s.repoFullName === opts.repo) && (!opts.status || s.status === opts.status))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, limit)
      .map((s) => structuredClone(s));
  }

  async listStaleSprites(olderThanHours: number): Promise<ScanRecord[]> {
    const cutoff = Date.now() - olderThanHours * 3600_000;
    return [...this.scans.values()]
      .filter(
        (s) =>
          s.spriteName !== null &&
          (s.spriteState === 'creating' || s.spriteState === 'running' || s.spriteState === 'sleeping') &&
          new Date(s.updatedAt).getTime() < cutoff,
      )
      .map((s) => structuredClone(s));
  }

  async saveFindings(findings: StoredFinding[]): Promise<void> {
    const now = new Date().toISOString();
    for (const f of findings) {
      this.findings.push({ ...structuredClone(f), id: randomUUID(), createdAt: now });
    }
  }

  async searchSimilarFindings(
    repoFullName: string,
    embedding: number[],
    opts: { limit?: number; excludeScanId?: string; minSimilarity?: number } = {},
  ): Promise<PastIncident[]> {
    const limit = opts.limit ?? 5;
    const minSim = opts.minSimilarity ?? 0.35;
    return this.findings
      .filter((f) => f.repoFullName === repoFullName && (!opts.excludeScanId || f.scanId !== opts.excludeScanId))
      .map((f) => ({
        item: f,
        similarity: cosineSimilarity(embedding, f.embedding),
      }))
      .filter((x) => x.similarity >= minSim)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit)
      .map(({ item, similarity }) => ({
        scanId: item.scanId,
        prNumber: item.prNumber,
        title: item.finding.title,
        category: item.finding.category,
        severity: item.finding.severity,
        filePath: item.finding.file,
        description: item.finding.exploitability,
        similarity: Math.round(similarity * 1000) / 1000,
        createdAt: item.createdAt,
      }));
  }

  async savePatch(patch: SavePatchInput): Promise<PatchRecord> {
    const now = new Date().toISOString();
    const rec: PatchRecord = {
      scanId: patch.scanId,
      summary: patch.summary,
      files: structuredClone(patch.files),
      diff: patch.diff,
      diffSha256: patch.diffSha256,
      verification: structuredClone(patch.verification),
      postMergeActions: [...patch.postMergeActions],
      generator: patch.generator,
      status: patch.status,
      approvedBy: null,
      commitSha: null,
      createdAt: now,
      approvedAt: null,
      pushedAt: null,
    };
    this.patches.set(patch.scanId, rec);
    return structuredClone(rec);
  }

  async getPatch(scanId: string): Promise<PatchRecord | null> {
    const p = this.patches.get(scanId);
    return p ? structuredClone(p) : null;
  }

  async updatePatch(scanId: string, patch: PatchUpdate): Promise<PatchRecord | null> {
    const cur = this.patches.get(scanId);
    if (!cur) return null;
    Object.assign(cur, {
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      ...(patch.verification !== undefined ? { verification: structuredClone(patch.verification) } : {}),
      ...(patch.approvedBy !== undefined ? { approvedBy: patch.approvedBy } : {}),
      ...(patch.commitSha !== undefined ? { commitSha: patch.commitSha } : {}),
      ...(patch.approvedAt !== undefined ? { approvedAt: patch.approvedAt } : {}),
      ...(patch.pushedAt !== undefined ? { pushedAt: patch.pushedAt } : {}),
    });
    return structuredClone(cur);
  }

  async claimPatchApproval(scanId: string, approver: string): Promise<PatchRecord | null> {
    const cur = this.patches.get(scanId);
    if (!cur) return null;
    if (cur.status !== 'verified' && cur.status !== 'verified_with_warnings') return null;
    cur.status = 'approved';
    cur.approvedBy = approver;
    cur.approvedAt = new Date().toISOString();
    return structuredClone(cur);
  }

  async getStats(): Promise<DashboardStats> {
    const all = [...this.scans.values()];
    const activeScans = all.filter((s) => s.status !== 'superseded');
    const audited = activeScans.filter((s) => s.status !== 'queued' && s.status !== 'running');
    const scored = activeScans.filter((s) => s.riskScore !== null);
    const avg =
      scored.length === 0 ? 0 : Math.round(scored.reduce((acc, s) => acc + (s.riskScore ?? 0), 0) / scored.length);

    return {
      prsAudited: audited.length,
      secretsBlocked: activeScans.reduce((acc, s) => acc + s.secretsCount, 0),
      averageRiskScore: avg,
      activeSprites: all.filter((s) => s.spriteState === 'creating' || s.spriteState === 'running').length,
      sleepingSprites: all.filter((s) => s.spriteState === 'sleeping').length,
      patchesPushed: all.filter((s) => s.status === 'pushed').length,
      awaitingApproval: all.filter((s) => s.status === 'awaiting_approval').length,
    };
  }
}

/* -------------------------------------------------------------------------------------------------
 * Factory
 * -----------------------------------------------------------------------------------------------*/

export function createStore(config: AppConfig, log: Logger): { store: Store; embeddings: EmbeddingClient } {
  const embeddings = new EmbeddingClient(config.embeddings, log.child({ module: 'embeddings' }));
  if (config.database.url) {
    return {
      store: new PostgresStore(config.database.url, config.database.ssl, log.child({ module: 'postgres' })),
      embeddings,
    };
  }
  if (!config.localSandboxMode) {
    throw new Error('DATABASE_URL is required when LOCAL_SANDBOX_MODE=false');
  }
  log.warn('DATABASE_URL not set — using in-memory store with local vector similarity search.');
  return { store: new InMemoryStore(), embeddings };
}
