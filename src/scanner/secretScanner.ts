import { createHash } from 'node:crypto';
import type { CommitPatch, SecretLeak, SecretSource, Severity } from '../types.js';

/**
 * Layer A — Static & Build Secret Scanner.
 *
 * Pure, dependency-free detection of exposed credentials using provider-specific
 * signatures plus Shannon-entropy analysis. Raw secret values never leave this
 * module except through {@link RedactionVault}, which lives only in the trusted
 * orchestrator's memory for the lifetime of a single audit.
 */

interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  /** Capture group holding the secret (0 = whole match). */
  group?: number;
  /** Minimum Shannon entropy (bits/char) of the captured secret. */
  minEntropy?: number;
  /** Severity override when the value looks like a test/sandbox credential. */
  testSeverity?: Severity;
  testMarker?: RegExp;
  /** Only applied to env-style files. */
  envOnly?: boolean;
}

export const SECRET_RULES: readonly SecretRule[] = [
  {
    id: 'private-key',
    name: 'Private Key Block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: 'critical',
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    group: 1,
    severity: 'critical',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    pattern: /aws.{0,24}(?:secret|private|key).{0,24}?["'`=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    group: 1,
    minEntropy: 3.8,
    severity: 'critical',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret / Restricted Key',
    pattern: /\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,99})\b/g,
    group: 1,
    severity: 'critical',
    testMarker: /_test_/,
    testSeverity: 'medium',
  },
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe Webhook Signing Secret',
    pattern: /\b(whsec_[0-9A-Za-z]{24,})\b/g,
    group: 1,
    severity: 'high',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    pattern: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,})/g,
    group: 1,
    severity: 'critical',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    pattern: /\b(sk-(?:proj-|svcacct-|admin-)?(?!ant-)[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})/g,
    group: 1,
    severity: 'critical',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{50,})\b/g,
    group: 1,
    severity: 'critical',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
    group: 1,
    severity: 'high',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    group: 1,
    severity: 'high',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    group: 1,
    severity: 'medium',
  },
  {
    id: 'connection-string-password',
    name: 'Credentialed Connection String',
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s/@'"]+:([^@\s'"]{6,})@[^\s'"]+/gi,
    group: 1,
    severity: 'high',
  },
  {
    id: 'generic-secret-assignment',
    name: 'Hardcoded Secret Assignment',
    pattern:
      /(?:api[_-]?key|apikey|secret|token|passwd|password|auth[_-]?key|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_]*["']?\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/gi,
    group: 1,
    minEntropy: 3.3,
    severity: 'high',
  },
  {
    id: 'env-file-secret',
    name: 'Secret in Committed .env File',
    pattern:
      /^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|CREDENTIAL|DSN|DATABASE_URL|PRIVATE)[A-Z0-9_]*)\s*=\s*["']?([^"'\s#]{8,})["']?/gim,
    group: 2,
    minEntropy: 2.5,
    severity: 'high',
    envOnly: true,
  },
];

const PLACEHOLDER_PATTERN =
  /^(?:x+|\*+|\.+|changeme|change_me|placeholder|example|your[_-]|<.*>|\$\{.*\}|\{\{.*\}\}|process\.env|os\.environ|env\(|getenv|null|undefined|none|true|false|redacted|dummy|test123|password\d*|secret\d*|sk_test_x+)/i;

const HIGH_ENTROPY_TOKEN = /(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/_-])/g;

const SKIP_LINE_PATTERN =
  /integrity|sha(?:1|256|384|512)-|"resolved"|sourceMappingURL|data:[a-z]+\/[a-z0-9.+-]+;base64|\bhash\b|checksum|nonce|<path |viewBox|\bd="M/i;

const SKIP_FILE_PATTERN =
  /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock)$|\.(?:png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|woff2?|ttf|eot|mp4|mp3|wasm|svg|lock)$/i;

export interface ScanOptions {
  file: string;
  source: SecretSource;
  commitSha?: string;
  /** Map of content line index (0-based) → real line number. Defaults to idx + 1. */
  lineNumbers?: number[];
  /** Enable generic high-entropy detection (noisy on minified bundles). */
  entropy?: boolean;
}

export interface RawSecretMatch extends SecretLeak {
  raw: string;
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function fingerprintSecret(raw: string): string {
  return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export function redactValue(raw: string): string {
  if (raw.startsWith('-----BEGIN')) return '-----BEGIN … PRIVATE KEY----- [redacted]';
  if (raw.length <= 8) return '*'.repeat(raw.length);
  const keep = raw.length >= 24 ? 4 : 2;
  return `${raw.slice(0, keep)}${'*'.repeat(Math.min(12, raw.length - keep * 2))}${raw.slice(-keep)}`;
}

export function isEnvFilePath(path: string): boolean {
  const base = path.split('/').pop() ?? path;
  return /^\.env(?:\..+)?$/i.test(base) && !/\.(?:example|sample|template|dist|defaults)$/i.test(base);
}

export function isScannablePath(path: string): boolean {
  return !SKIP_FILE_PATTERN.test(path);
}

function looksLikePlaceholder(value: string): boolean {
  if (PLACEHOLDER_PATTERN.test(value)) return true;
  if (/^(.)\1+$/.test(value)) return true;
  if (/^[a-z]+$/.test(value) && value.length < 20) return true;
  return false;
}

function hasCharClassMix(value: string): boolean {
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  return classes >= 3;
}

/** Scan arbitrary text content and return matches including the raw value (trusted use only). */
export function scanTextRaw(content: string, opts: ScanOptions): RawSecretMatch[] {
  if (!isScannablePath(opts.file) && opts.source !== 'runtime_output') return [];
  const isEnv = isEnvFilePath(opts.file);
  const lines = content.split(/\r?\n/);
  const results: RawSecretMatch[] = [];

  lines.forEach((line, idx) => {
    if (line.length > 20_000) line = line.slice(0, 20_000);
    const lineNo = opts.lineNumbers?.[idx] ?? idx + 1;
    const spans: Array<{ start: number; end: number }> = [];

    for (const rule of SECRET_RULES) {
      if (rule.envOnly && !isEnv) continue;
      rule.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.pattern.exec(line)) !== null) {
        if (m[0].length === 0) {
          rule.pattern.lastIndex++;
          continue;
        }
        const raw = m[rule.group ?? 0];
        if (!raw) continue;
        const start = m.index + m[0].indexOf(raw);
        const end = start + raw.length;
        if (spans.some((s) => start < s.end && end > s.start)) continue;
        if (rule.id !== 'private-key' && looksLikePlaceholder(raw)) continue;
        const entropy = shannonEntropy(raw);
        if (rule.minEntropy !== undefined && entropy < rule.minEntropy) continue;
        const severity = rule.testMarker && rule.testMarker.test(raw) && rule.testSeverity ? rule.testSeverity : rule.severity;
        spans.push({ start, end });
        results.push(buildMatch(rule.id, rule.name, severity, raw, entropy, line, lineNo, opts));
      }
    }

    if (opts.entropy !== false && !SKIP_LINE_PATTERN.test(line)) {
      HIGH_ENTROPY_TOKEN.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = HIGH_ENTROPY_TOKEN.exec(line)) !== null) {
        const raw = m[1];
        if (!raw) continue;
        const start = m.index;
        const end = start + raw.length;
        if (spans.some((s) => start < s.end && end > s.start)) continue;
        if (/^[a-f0-9]+$/i.test(raw)) continue; // hashes / commit SHAs
        if (raw.includes('/') && /^[A-Za-z0-9_./-]+$/.test(raw) && raw.split('/').length > 2) continue; // paths
        if (!hasCharClassMix(raw) || looksLikePlaceholder(raw)) continue;
        const entropy = shannonEntropy(raw);
        if (entropy < 4.5) continue;
        spans.push({ start, end });
        results.push(buildMatch('high-entropy-string', 'High-Entropy String', 'medium', raw, entropy, line, lineNo, opts));
      }
    }
  });

  return results;
}

function buildMatch(
  ruleId: string,
  ruleName: string,
  severity: Severity,
  raw: string,
  entropy: number,
  line: string,
  lineNo: number,
  opts: ScanOptions,
): RawSecretMatch {
  const context = line.split(raw).join(redactValue(raw)).trim().slice(0, 240);
  const leak: RawSecretMatch = {
    ruleId,
    ruleName,
    severity,
    source: opts.source,
    file: opts.file,
    line: lineNo,
    redacted: redactValue(raw),
    fingerprint: fingerprintSecret(raw),
    entropy: Math.round(entropy * 100) / 100,
    context,
    raw,
  };
  if (opts.commitSha) leak.commitSha = opts.commitSha;
  return leak;
}

/** Strip raw secret values before persisting / displaying. */
export function toPublicLeak(match: RawSecretMatch): SecretLeak {
  const { raw: _raw, ...leak } = match;
  return leak;
}

export interface ParsedDiffFile {
  path: string;
  addedLines: Array<{ line: number; text: string }>;
  deleted: boolean;
}

/** Parse a unified diff and extract added lines with their new-file line numbers. */
export function parseUnifiedDiff(diff: string): ParsedDiffFile[] {
  const files: ParsedDiffFile[] = [];
  let current: ParsedDiffFile | null = null;
  let newLine = 0;
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith('diff --git ')) {
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
      current = { path: m?.[2] ?? 'unknown', addedLines: [], deleted: false };
      files.push(current);
      continue;
    }
    if (line.startsWith('+++ ')) {
      const p = line.slice(4).trim();
      if (p === '/dev/null') {
        if (current) current.deleted = true;
      } else {
        const path = p.replace(/^b\//, '');
        if (!current) {
          current = { path, addedLines: [], deleted: false };
          files.push(current);
        } else current.path = path;
      }
      continue;
    }
    if (line.startsWith('--- ')) continue;
    if (line.startsWith('@@')) {
      const m = /@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      newLine = m?.[1] ? Number.parseInt(m[1], 10) : 0;
      continue;
    }
    if (!current) continue;
    if (line.startsWith('+')) {
      current.addedLines.push({ line: newLine, text: line.slice(1) });
      newLine++;
    } else if (line.startsWith(' ')) {
      newLine++;
    }
  }
  return files;
}

/** Scan only the *added* lines of a unified diff. */
export function scanUnifiedDiffRaw(diff: string, source: SecretSource = 'diff', commitSha?: string): RawSecretMatch[] {
  const out: RawSecretMatch[] = [];
  for (const file of parseUnifiedDiff(diff)) {
    if (file.deleted || file.addedLines.length === 0) continue;
    const opts: ScanOptions = {
      file: file.path,
      source,
      lineNumbers: file.addedLines.map((l) => l.line),
      entropy: true,
    };
    if (commitSha) opts.commitSha = commitSha;
    out.push(...scanTextRaw(file.addedLines.map((l) => l.text).join('\n'), opts));
  }
  return out;
}

/** Scan every commit in the PR — catches secrets that were added and later "removed". */
export function scanCommitPatchesRaw(commits: CommitPatch[]): RawSecretMatch[] {
  const out: RawSecretMatch[] = [];
  for (const commit of commits) {
    for (const f of commit.files) {
      if (!f.patch) continue;
      const synthetic = `diff --git a/${f.filename} b/${f.filename}\n+++ b/${f.filename}\n${f.patch}`;
      out.push(...scanUnifiedDiffRaw(synthetic, 'commit', commit.sha));
    }
  }
  return out;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** De-duplicate leaks by (fingerprint, file), preferring the most severe / earliest source. */
export function dedupeLeaks<T extends SecretLeak>(leaks: T[]): T[] {
  const best = new Map<string, T>();
  for (const leak of leaks) {
    const key = `${leak.fingerprint}:${leak.file}`;
    const existing = best.get(key);
    if (!existing || SEVERITY_RANK[leak.severity] > SEVERITY_RANK[existing.severity]) best.set(key, leak);
  }
  return [...best.values()].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file) || a.line - b.line,
  );
}

/**
 * Holds raw secret values in trusted memory so that text sent to the LLM can be
 * redacted, and model-produced search strings can be mapped back to originals.
 */
export class RedactionVault {
  private readonly byRaw = new Map<string, string>();
  private readonly byToken = new Map<string, string>();

  register(match: RawSecretMatch): string {
    const existing = this.byRaw.get(match.raw);
    if (existing) return existing;
    const token = `[REDACTED_SECRET_${this.byRaw.size + 1}:${match.ruleId}]`;
    this.byRaw.set(match.raw, token);
    this.byToken.set(token, match.raw);
    return token;
  }

  registerAll(matches: RawSecretMatch[]): void {
    // Longest first so overlapping secrets redact cleanly.
    [...matches].sort((a, b) => b.raw.length - a.raw.length).forEach((m) => this.register(m));
  }

  redact(text: string): string {
    let out = text;
    const raws = [...this.byRaw.keys()].sort((a, b) => b.length - a.length);
    for (const raw of raws) {
      const token = this.byRaw.get(raw);
      if (token) out = out.split(raw).join(token);
    }
    return out;
  }

  unredact(text: string): string {
    let out = text;
    for (const [token, raw] of this.byToken) out = out.split(token).join(raw);
    return out;
  }

  containsToken(text: string): boolean {
    return /\[REDACTED_SECRET_\d+:[a-z0-9-]+\]/.test(text);
  }

  get size(): number {
    return this.byRaw.size;
  }
}
