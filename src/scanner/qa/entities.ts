import { fuzzyTokenMatch, splitIdentifier, stemToken } from './normalize.js';
import type {
  DeterministicAuditPayload,
  DeterministicEgressEvent,
  DeterministicFinding,
  DeterministicSeverity,
  EntityResolution,
  NormalizedQuery,
} from './types.js';

/**
 * Stage 3 — Entity-first lookup across files, lines, domains, finding titles,
 * categories, fingerprints, redacted secrets, severities, and ordinals.
 */

export const SEVERITY_ORDER: Readonly<Record<DeterministicSeverity, number>> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function isSecretFinding(f: DeterministicFinding): boolean {
  const cat = (f.category || '').toLowerCase();
  return cat === 'secret' || cat === 'secret_leak' || cat === 'data_exposure' || cat === 'credential';
}

export function isEgressFinding(f: DeterministicFinding): boolean {
  const cat = (f.category || '').toLowerCase();
  return cat === 'egress' || cat === 'malicious_egress' || cat === 'network';
}

export function sortFindingsByPriority(findings: readonly DeterministicFinding[]): DeterministicFinding[] {
  return findings
    .map((f, idx) => ({ f, idx }))
    .sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[b.f.severity] ?? 0) - (SEVERITY_ORDER[a.f.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      const riskDiff = (b.f.riskContribution ?? 0) - (a.f.riskContribution ?? 0);
      if (riskDiff !== 0) return riskDiff;
      const rtA = a.f.source === 'runtime' || Boolean(a.f.runtimeProof) ? 1 : 0;
      const rtB = b.f.source === 'runtime' || Boolean(b.f.runtimeProof) ? 1 : 0;
      if (rtB !== rtA) return rtB - rtA;
      return a.idx - b.idx;
    })
    .map((x) => x.f);
}

const CODE_EXTENSIONS = new Set([
  'js',
  'ts',
  'jsx',
  'tsx',
  'mjs',
  'cjs',
  'py',
  'go',
  'rb',
  'rs',
  'java',
  'kt',
  'php',
  'sh',
  'bash',
  'json',
  'yml',
  'yaml',
  'toml',
  'env',
  'md',
  'txt',
  'sql',
  'html',
  'css',
  'scss',
  'xml',
  'lock',
  'cfg',
  'ini',
  'tf',
]);

const DOMAIN_TLD_PATTERN =
  /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi;

const DOMAIN_TLDS = new Set([
  'com',
  'org',
  'net',
  'io',
  'dev',
  'invalid',
  'co',
  'app',
  'ai',
  'gov',
  'edu',
  'xyz',
  'site',
  'cloud',
  'internal',
  'local',
  'test',
  'example',
  'info',
  'me',
  'gg',
  'sh',
  'cc',
  'ru',
  'cn',
  'uk',
  'de',
  'fr',
]);

const RESERVED_NON_TITLE_TOKENS = new Set([
  'sprite',
  'sandbox',
  'metadata',
  'checkpoint',
  'summary',
  'report',
  'status',
  'branch',
  'commit',
  'approve',
  'merge',
  'patch',
  'diff',
  'evidence',
  'egress',
]);

const GENERIC_TITLE_WORDS = new Set([
  'hardcoded',
  'detected',
  'potential',
  'found',
  'issue',
  'finding',
  'security',
  'vulnerability',
  'unauthorized',
  'malicious',
  'outbound',
  'external',
  'network',
  'secret',
  'credential',
  'token',
  'egress',
  'traffic',
  'script',
  'during',
  'phase',
  'source',
  'value',
  'string',
  'error',
]);

export function extractDiffFilenames(diff?: string | null): string[] {
  if (!diff) return [];
  const files = new Set<string>();
  for (const line of diff.split(/\r?\n/)) {
    const m1 = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
    if (m1?.[2]) files.add(m1[2].trim());
    const m2 = /^\+\+\+ b\/(.+)$/.exec(line);
    if (m2?.[1] && m2[1] !== '/dev/null') files.add(m2[1].trim());
    const m3 = /^--- a\/(.+)$/.exec(line);
    if (m3?.[1] && m3[1] !== '/dev/null') files.add(m3[1].trim());
  }
  return [...files];
}

function basenameOf(filePath: string): string {
  const parts = filePath.split('/');
  return parts[parts.length - 1] ?? filePath;
}

function stemOfFilename(filePath: string): string {
  const base = basenameOf(filePath);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(0, dot) : base;
}

function extractHostFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function resolveEntities(nq: NormalizedQuery, audit: DeterministicAuditPayload): EntityResolution {
  const sortedFindings = sortFindingsByPriority(audit.findings ?? []);
  const egressEvents = audit.egressEvents ?? [];

  const matchedFindingIds = new Set<string>();
  const matchedFiles = new Set<string>();
  const matchedDomainsMap = new Map<string, DeterministicEgressEvent>();
  const absentDomains = new Set<string>();
  let requestedLine: number | null = null;
  let matchStrength: 'exact' | 'fuzzy' | 'none' = 'none';
  let requestedFailingTest = false;
  let requestedCategory: 'secret' | 'egress' | 'code' | null = null;

  const bumpStrength = (s: 'exact' | 'fuzzy') => {
    if (s === 'exact') matchStrength = 'exact';
    else if (matchStrength === 'none') matchStrength = 'fuzzy';
  };

  // 1. Collect all known file paths across findings + patch.diff
  const knownFiles = new Set<string>();
  for (const f of sortedFindings) {
    if (f.file) knownFiles.add(f.file);
  }
  for (const df of extractDiffFilenames(audit.patch?.diff)) {
    knownFiles.add(df);
  }

  // Extract explicit file:line references from raw query (e.g. payment.js:2)
  const fileLineMatches = [...nq.raw.matchAll(/([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+):(\d+)/g)];
  for (const flm of fileLineMatches) {
    const refPath = (flm[1] ?? '').toLowerCase();
    const refLine = Number.parseInt(flm[2] ?? '', 10);
    if (Number.isFinite(refLine)) requestedLine = refLine;
    for (const file of knownFiles) {
      const fLow = file.toLowerCase();
      const baseLow = basenameOf(file).toLowerCase();
      if (fLow === refPath || baseLow === refPath || fLow.endsWith(`/${refPath}`)) {
        matchedFiles.add(file);
        bumpStrength('exact');
      } else if (fuzzyTokenMatch(refPath, baseLow)) {
        matchedFiles.add(file);
        bumpStrength('fuzzy');
      }
    }
  }

  // Match file paths, basenames, and stems against query text & tokens
  for (const file of knownFiles) {
    const fLow = file.toLowerCase();
    const baseLow = basenameOf(file).toLowerCase();
    const stemLow = stemOfFilename(file).toLowerCase();

    if (nq.lower.includes(fLow) || (baseLow.length >= 4 && nq.lower.includes(baseLow))) {
      matchedFiles.add(file);
      bumpStrength('exact');
      continue;
    }

    for (const tok of nq.tokens) {
      const tokClean = tok.replace(/:\d+$/, '');
      if (tokClean === baseLow || tokClean === fLow) {
        matchedFiles.add(file);
        bumpStrength('exact');
        break;
      }
      // Fuzzy match against filename with extension (e.g. paymnet.js -> payment.js)
      if (tokClean.includes('.') && fuzzyTokenMatch(tokClean, baseLow)) {
        matchedFiles.add(file);
        bumpStrength('fuzzy');
        break;
      }
      // Match against file stem (e.g. "payment" or "telementary" -> telemetry.js), guard stem >= 4
      if (stemLow.length >= 4 && !['index', 'utils', 'index', 'config', 'types', 'model', 'tests'].includes(stemLow)) {
        const m = fuzzyTokenMatch(tokClean, stemLow);
        if (m) {
          matchedFiles.add(file);
          bumpStrength(m);
          break;
        }
      }
    }
  }

  // Attach findings belonging to matched files
  if (matchedFiles.size > 0) {
    for (const f of sortedFindings) {
      if (matchedFiles.has(f.file)) {
        if (requestedLine === null || f.line === requestedLine) {
          matchedFindingIds.add(f.id);
        }
      }
    }
    // If file matched with a line that didn't exist, still include findings in that file
    if (matchedFindingIds.size === 0) {
      for (const f of sortedFindings) {
        if (matchedFiles.has(f.file)) matchedFindingIds.add(f.id);
      }
    }
  }

  // 2. Domain / Hostname lookup (exact, partial token, or fuzzy) + absent domain detection
  const knownDomainsLower = new Set<string>();
  for (const ev of egressEvents) {
    if (!ev.domain) continue;
    const dLow = ev.domain.toLowerCase();
    knownDomainsLower.add(dLow);
    const domainParts = splitIdentifier(dLow).filter((p) => p.length >= 4 && !DOMAIN_TLDS.has(p));
    const urlHosts = (ev.sampleUrls ?? [])
      .map(extractHostFromUrl)
      .filter((h): h is string => Boolean(h));
    for (const uh of urlHosts) knownDomainsLower.add(uh);

    if (nq.lower.includes(dLow) || urlHosts.some((h) => nq.lower.includes(h))) {
      matchedDomainsMap.set(dLow, ev);
      bumpStrength('exact');
      continue;
    }

    // Check host prefix without TLD (e.g. "telemetry-collector")
    const hostWithoutTld = dLow.replace(/\.[a-z0-9-]+$/, '');
    if (hostWithoutTld.length >= 5 && nq.lower.includes(hostWithoutTld)) {
      matchedDomainsMap.set(dLow, ev);
      bumpStrength('exact');
      continue;
    }

    for (const tok of nq.tokens) {
      const tokHost = tok.replace(/:\d+$/, '');
      if (tokHost.includes('.') && fuzzyTokenMatch(tokHost, dLow)) {
        matchedDomainsMap.set(dLow, ev);
        bumpStrength('fuzzy');
        break;
      }
      if (domainParts.some((dp) => dp.length >= 6 && fuzzyTokenMatch(tokHost, dp))) {
        // Avoid colliding a shared stem like "telemetry" when user clearly asked about telemetry.js
        const askedFile = matchedFiles.size > 0 && [...matchedFiles].some((mf) => mf.toLowerCase().includes(tokHost));
        if (!askedFile) {
          matchedDomainsMap.set(dLow, ev);
          bumpStrength('fuzzy');
          break;
        }
      }
    }
  }

  // Attach findings associated with matched domains
  if (matchedDomainsMap.size > 0) {
    for (const ev of matchedDomainsMap.values()) {
      if (ev.associatedFindingId) matchedFindingIds.add(ev.associatedFindingId);
    }
    for (const f of sortedFindings) {
      if (isEgressFinding(f)) {
        const blob = `${f.title} ${f.evidence ?? ''} ${f.runtimeProof ?? ''}`.toLowerCase();
        for (const dLow of matchedDomainsMap.keys()) {
          if (blob.includes(dLow)) matchedFindingIds.add(f.id);
        }
      }
    }
  }

  // Detect explicit domains mentioned in query that are NOT in audit.egressEvents (e.g. google.com)
  DOMAIN_TLD_PATTERN.lastIndex = 0;
  let dm: RegExpExecArray | null;
  while ((dm = DOMAIN_TLD_PATTERN.exec(nq.raw)) !== null) {
    const candidate = (dm[1] ?? '').toLowerCase();
    const tld = candidate.split('.').pop() ?? '';
    if (CODE_EXTENSIONS.has(tld) && !DOMAIN_TLDS.has(tld)) continue;
    if (!DOMAIN_TLDS.has(tld)) continue;
    // Skip if it looks like a JS member access like process.env or console.log
    if (candidate === 'process.env' || candidate.startsWith('process.')) continue;
    // Skip if it matches a known file
    const isKnownFile = [...knownFiles].some(
      (f) => f.toLowerCase() === candidate || basenameOf(f).toLowerCase() === candidate,
    );
    if (isKnownFile) continue;
    // Skip if already matched or fuzzy-matched to a known egress domain
    if (knownDomainsLower.has(candidate)) continue;
    const isFuzzyKnown = [...knownDomainsLower].some((kd) => fuzzyTokenMatch(candidate, kd) !== null);
    if (!isFuzzyKnown) {
      absentDomains.add(candidate);
      bumpStrength('exact');
    }
  }

  // 3. Finding title, fingerprint, redacted secret prefix/suffix lookup
  for (const f of sortedFindings) {
    // Fingerprint match (>= 6 hex chars)
    if (f.fingerprint && f.fingerprint.length >= 6) {
      const fpLow = f.fingerprint.toLowerCase();
      for (const tok of nq.tokens) {
        if (tok.length >= 6 && fpLow.startsWith(tok)) {
          matchedFindingIds.add(f.id);
          bumpStrength('exact');
        }
      }
    }

    // Redacted secret prefix / suffix match (e.g. sk_l, 4321)
    if (f.redactedSecret) {
      const redLow = f.redactedSecret.toLowerCase();
      if (redLow.length >= 6 && nq.lower.includes(redLow)) {
        matchedFindingIds.add(f.id);
        bumpStrength('exact');
      } else {
        const prefix = redLow.slice(0, 4);
        const suffix = redLow.slice(-4);
        if (prefix.length === 4 && /[a-z]/.test(prefix) && nq.tokens.some((t) => t === prefix || t.startsWith(prefix))) {
          if (prefix.includes('_') || prefix.startsWith('akia') || prefix.startsWith('ghp') || prefix.startsWith('xox')) {
            matchedFindingIds.add(f.id);
            bumpStrength('exact');
          }
        }
        if (suffix.length === 4 && /\d/.test(suffix) && nq.tokens.includes(suffix)) {
          matchedFindingIds.add(f.id);
          bumpStrength('exact');
        }
      }
    }

    // Specific finding title tokens (e.g. "stripe", "aws", "postinstall", "injection")
    const titleTokens = splitIdentifier(f.title)
      .map(stemToken)
      .filter((t) => t.length >= 4 && !GENERIC_TITLE_WORDS.has(t));
    for (const tt of titleTokens) {
      for (const qt of nq.identifierTokens) {
        if (RESERVED_NON_TITLE_TOKENS.has(qt) && qt !== tt) continue;
        const m = fuzzyTokenMatch(qt, tt);
        if (m) {
          matchedFindingIds.add(f.id);
          bumpStrength(m);
          break;
        }
      }
    }
  }

  // 4. Ordinal & Severity references ("the critical issue", "finding #2", "second finding", "the failing test")
  if (/\b(?:the\s+)?fail(?:ed|ing)\s+test\b/i.test(nq.raw)) {
    requestedFailingTest = true;
    bumpStrength('exact');
  }

  const ordMatch =
    /\b(?:finding|issue|item|vuln|vulnerability)\s*#?\s*(\d+)\b/i.exec(nq.raw) ??
    /(?:^|\s)#(\d+)\b/.exec(nq.raw);
  if (ordMatch?.[1]) {
    const idx = Number.parseInt(ordMatch[1], 10) - 1;
    const target = sortedFindings[idx];
    if (target) {
      matchedFindingIds.add(target.id);
      bumpStrength('exact');
    }
  }

  const wordOrdinals: Array<[RegExp, number]> = [
    [/\b(?:the\s+)?first\s+(?:finding|issue|one|vuln|item)\b/i, 0],
    [/\b(?:the\s+)?second\s+(?:finding|issue|one|vuln|item)\b/i, 1],
    [/\b(?:the\s+)?third\s+(?:finding|issue|one|vuln|item)\b/i, 2],
    [/\b(?:the\s+)?fourth\s+(?:finding|issue|one|vuln|item)\b/i, 3],
  ];
  for (const [pat, idx] of wordOrdinals) {
    if (pat.test(nq.raw) && sortedFindings[idx]) {
      matchedFindingIds.add(sortedFindings[idx]!.id);
      bumpStrength('exact');
    }
  }

  // Severity pointers ("the critical issue", "the high severity one", "any criticals")
  const sevPointers: Array<[RegExp, DeterministicSeverity]> = [
    [/\b(?:the\s+)?critical(?:\s+severity)?\s+(?:issue|finding|one|vuln|bug|item)\b/i, 'critical'],
    [/\b(?:the\s+)?high(?:\s+severity)?\s+(?:issue|finding|one|vuln|bug|item)\b/i, 'high'],
    [/\b(?:the\s+)?medium(?:\s+severity)?\s+(?:issue|finding|one|vuln|bug|item)\b/i, 'medium'],
    [/\b(?:the\s+)?low(?:\s+severity)?\s+(?:issue|finding|one|vuln|bug|item)\b/i, 'low'],
  ];
  for (const [pat, sev] of sevPointers) {
    if (pat.test(nq.raw)) {
      for (const f of sortedFindings) {
        if (f.severity === sev) {
          matchedFindingIds.add(f.id);
          bumpStrength('exact');
        }
      }
    }
  }

  // Detect explicit category hint for empty-state awareness
  if (/\b(?:secret|key|credential|token|password|privkey|pem|\.env)\b/i.test(nq.lower)) {
    requestedCategory = 'secret';
  } else if (/\b(?:egress|domain|outbound|network|exfil|c2|beacon|callback)\b/i.test(nq.lower)) {
    requestedCategory = 'egress';
  }

  const matchedFindings = sortedFindings.filter((f) => matchedFindingIds.has(f.id));
  const matchedDomains = [...matchedDomainsMap.values()];
  const isEntityScoped =
    matchedFindings.length > 0 ||
    matchedFiles.size > 0 ||
    matchedDomains.length > 0 ||
    absentDomains.size > 0 ||
    requestedFailingTest;

  return {
    matchedFindings,
    matchedFiles: [...matchedFiles],
    matchedDomains,
    absentDomains: [...absentDomains],
    requestedLine,
    requestedFailingTest,
    matchStrength,
    isEntityScoped,
    resolvedFromMemory: false,
    requestedCategory,
  };
}
