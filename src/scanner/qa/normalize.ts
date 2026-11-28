import type { NormalizedQuery } from './types.js';

/**
 * Stage 1 — Pre-processing, noise stripping, stemming, synonym/shorthand mapping,
 * identifier tokenization, and length-guarded Levenshtein fuzzy matcher.
 */

// eslint-disable-next-line no-control-regex
const ANSI_PATTERN = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, '');
}

const PROMPT_INJECTION_PATTERNS: readonly RegExp[] = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?|directions?)\b/i,
  /\b(?:disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|your|system)\s+(?:instructions?|rules?|prompts?)\b/i,
  /\b(?:print|reveal|show|dump|leak|output|repeat)\s+(?:your\s+)?(?:system\s+|hidden\s+|initial\s+)?prompt\b/i,
  /\bact\s+as\s+(?:a|an)\b/i,
  /\byou\s+are\s+now\s+(?:a|an|in)\b/i,
];

export function isPromptInjection(raw: string): boolean {
  return PROMPT_INJECTION_PATTERNS.some((p) => p.test(raw));
}

const FILLER_PATTERNS: readonly RegExp[] = [
  /@spriteguard\b[:,]?\s*/gi,
  /\/spriteguard\b\s*/gi,
  /\bhey\s+can\s+you\s+tell\s+me\b/gi,
  /\bcan\s+(?:gemini|claude|ai|you)\s+answer\s+this\b/gi,
  /\bwhat['’]?s\s+going\s+on\s+with\b/gi,
  /\bplease\s+explain\b/gi,
  /\bcould\s+you\s+(?:please\s+)?(?:check|tell\s+me|explain)\b/gi,
  /\bcan\s+you\s+(?:please\s+)?(?:check|tell\s+me|explain)\b/gi,
  /\bi\s+want\s+to\s+know\b/gi,
  /\bhey\b[:,!]?\s*/gi,
  /\bplease\b[:,!]?\s*/gi,
  /\bthanks?\b[:,!]?\s*/gi,
];

const STEM_MAP: Readonly<Record<string, string>> = {
  keys: 'key',
  secrets: 'secret',
  secert: 'secret',
  secerts: 'secret',
  credentials: 'credential',
  creds: 'credential',
  cred: 'credential',
  tokens: 'token',
  leaks: 'leak',
  leaked: 'leak',
  leaking: 'leak',
  leked: 'leak',
  exposed: 'expose',
  exposing: 'expose',
  exposure: 'expose',
  exposures: 'expose',
  failed: 'fail',
  failing: 'fail',
  fails: 'fail',
  failure: 'fail',
  failures: 'fail',
  domains: 'domain',
  domian: 'domain',
  domians: 'domain',
  hosts: 'host',
  hostnames: 'hostname',
  urls: 'url',
  endpoints: 'endpoint',
  patches: 'patch',
  patched: 'patch',
  patching: 'patch',
  fixes: 'fix',
  fixed: 'fix',
  fixing: 'fix',
  remediations: 'remediation',
  remediate: 'remediation',
  remediating: 'remediation',
  solving: 'solve',
  solved: 'solve',
  tests: 'test',
  testing: 'test',
  tested: 'test',
  files: 'file',
  lines: 'line',
  paths: 'path',
  risks: 'risk',
  risky: 'risk',
  exploits: 'exploit',
  exploitable: 'exploit',
  exploitability: 'exploit',
  dangerous: 'danger',
  dangers: 'danger',
  impacts: 'impact',
  approving: 'approve',
  approved: 'approve',
  approval: 'approve',
  aprove: 'approve',
  merging: 'merge',
  merged: 'merge',
  merges: 'merge',
  commits: 'commit',
  committed: 'commit',
  committing: 'commit',
  pushes: 'push',
  pushed: 'push',
  pushing: 'push',
  changes: 'change',
  changed: 'change',
  changing: 'change',
  edits: 'edit',
  edited: 'edit',
  editing: 'edit',
  diffs: 'diff',
  hunks: 'hunk',
  findings: 'finding',
  issues: 'issue',
  vulnerabilities: 'vulnerability',
  vulns: 'vuln',
  criticals: 'critical',
  severities: 'severity',
  egresses: 'egress',
  egres: 'egress',
  ports: 'port',
  hits: 'hit',
  errors: 'error',
  warnings: 'warning',
  canaries: 'canary',
  sprites: 'sprite',
  sandboxes: 'sandbox',
  commands: 'command',
  steps: 'step',
  actions: 'action',
  instructions: 'instruction',
  comments: 'comment',
  messages: 'message',
  reports: 'report',
  summaries: 'summary',
  summarize: 'summary',
  summarizing: 'summary',
  whre: 'where',
  flagged: 'flag',
  flags: 'flag',
  flagging: 'flag',
  blocked: 'block',
  blocking: 'block',
  blocks: 'block',
  passed: 'pass',
  passing: 'pass',
  passes: 'pass',
  rotated: 'rotate',
  rotating: 'rotate',
  rotation: 'rotate',
  revoked: 'revoke',
  revoking: 'revoke',
  revocation: 'revoke',
  ignored: 'ignore',
  ignoring: 'ignore',
  dismissed: 'dismiss',
  suppressed: 'suppress',
  overridden: 'override',
  shipped: 'ship',
  shipping: 'ship',
  ships: 'ship',
  hacked: 'hack',
  hacking: 'hack',
};

export function stemToken(token: string): string {
  const lower = token.toLowerCase();
  if (STEM_MAP[lower]) return STEM_MAP[lower];
  if (lower.length > 5 && lower.endsWith('ies')) return `${lower.slice(0, -3)}y`;
  if (lower.length > 5 && lower.endsWith('ing')) {
    const base = lower.slice(0, -3);
    if (STEM_MAP[base]) return STEM_MAP[base];
  }
  if (lower.length > 4 && lower.endsWith('s') && !lower.endsWith('ss') && !lower.endsWith('us') && !lower.endsWith('is')) {
    const singular = lower.slice(0, -1);
    if (STEM_MAP[singular]) return STEM_MAP[singular];
  }
  return lower;
}

/**
 * Split camelCase, PascalCase, snake_case, kebab-case, paths, and dot-delimited identifiers.
 */
export function splitIdentifier(raw: string): string[] {
  if (!raw) return [];
  const withSpaces = raw
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[/_.:\\-]+/g, ' ');
  return withSpaces
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

/**
 * Classic Levenshtein edit distance (O(m*n), zero dependencies).
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const al = a.length;
  const bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;

  let prev = new Array<number>(bl + 1);
  let curr = new Array<number>(bl + 1);
  for (let j = 0; j <= bl; j++) prev[j] = j;

  for (let i = 1; i <= al; i++) {
    curr[0] = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= bl; j++) {
      const cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min((prev[j] ?? 0) + 1, (curr[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[bl] ?? 0;
}

/**
 * Length-guarded fuzzy token matching:
 *  - length <= 3: exact match ONLY (prevents 'is'/'in'/'to' colliding with 'ip'/'ci'/'pr')
 *  - length 4..5: Levenshtein distance <= 1
 *  - length >= 6: Levenshtein distance <= 2
 */
export function fuzzyTokenMatch(queryToken: string, targetToken: string): 'exact' | 'fuzzy' | null {
  const q = queryToken.toLowerCase();
  const t = targetToken.toLowerCase();
  if (!q || !t) return null;
  if (q === t) return 'exact';

  const minLen = Math.min(q.length, t.length);
  if (minLen <= 3) return null;

  const maxDist = minLen <= 5 ? 1 : 2;
  if (Math.abs(q.length - t.length) > maxDist) return null;

  return levenshtein(q, t) <= maxDist ? 'fuzzy' : null;
}

const VAGUE_SHORT_SET = new Set([
  'why',
  'what',
  'details',
  'detail',
  'more',
  'explain',
  'status',
  'info',
  'elaborate',
  'huh',
]);

export function normalizeQuery(rawQuestion: string): NormalizedQuery {
  const raw = rawQuestion.slice(0, 500).trim();
  const injection = isPromptInjection(raw);

  let cleaned = stripAnsi(raw);
  for (const pat of FILLER_PATTERNS) {
    cleaned = cleaned.replace(pat, ' ');
  }
  // Preserve dots inside filenames/domains, colons in file:line, # in #1, and _ / - for identifier tokenization
  cleaned = cleaned
    .replace(/[?!,;()"'`~*^&+={}[\]|<>]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const lower = cleaned.toLowerCase();
  const tokens = lower
    .split(/\s+/)
    .map((t) => t.replace(/^[.:-]+|[.:-]+$/g, ''))
    .filter((t) => t.length > 0);

  const stemmedTokens = tokens.map((t) => stemToken(t));

  const idSet = new Set<string>();
  for (const tok of tokens) {
    idSet.add(tok);
    idSet.add(stemToken(tok));
    for (const part of splitIdentifier(tok)) {
      idSet.add(part);
      idSet.add(stemToken(part));
    }
  }
  const identifierTokens = [...idSet];

  const hasCompoundJoiner = /\b(?:and|also|plus|as\s+well\s+as)\b/i.test(raw);
  const nonStopTokens = stemmedTokens.filter(
    (t) => !['the', 'a', 'an', 'is', 'it', 'this', 'that', 'me', 'give', 'tell', 'show'].includes(t),
  );
  const isShortVague =
    !injection &&
    nonStopTokens.length > 0 &&
    nonStopTokens.length <= 2 &&
    nonStopTokens.every((t) => VAGUE_SHORT_SET.has(t));

  return {
    raw,
    cleaned,
    lower,
    tokens,
    stemmedTokens,
    identifierTokens,
    hasCompoundJoiner,
    isShortVague,
    isPromptInjection: injection,
  };
}
