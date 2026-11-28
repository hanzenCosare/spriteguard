import { isEgressFinding, isSecretFinding } from './entities.js';
import { fuzzyTokenMatch } from './normalize.js';
import type { EntityResolution, IntentId, NormalizedQuery, ScoredIntent } from './types.js';

/**
 * Stage 4 — Weighted multi-intent confidence scorer, semantic concept cluster router,
 * and deterministic tie-breaker.
 */

export const INTENT_TIE_ORDER: readonly IntentId[] = [
  'boolean',
  'quantitative',
  'comparison',
  'fix',
  'secrets',
  'egress',
  'exploit',
  'location',
  'approve',
  'diff',
  'evidence',
  'draft',
  'next_steps',
  'false_positive',
  'metadata',
  'full_report',
  'summary',
];

const TIE_RANK: Readonly<Record<IntentId, number>> = Object.fromEntries(
  INTENT_TIE_ORDER.map((id, i) => [id, i]),
) as Record<IntentId, number>;

interface IntentRuleSpec {
  exactKeywords: readonly string[];
  shorthandTokens: readonly string[];
  phrases: ReadonlyArray<{ pattern: RegExp; weight: number; label: string }>;
}

const INTENT_RULES: Readonly<Record<IntentId, IntentRuleSpec>> = {
  secrets: {
    exactKeywords: ['secret', 'key', 'token', 'credential', 'leak', 'expose', 'password', 'apikey', 'privkey', 'pem', 'fingerprint', 'entropy'],
    shorthandTokens: ['env', 'hardcoded', 'pwd', 'creds', 'rotate', 'revoke', 'stripe', 'aws', 'github'],
    phrases: [
      { pattern: /\bapi\s+key\b/i, weight: 5, label: 'phrase:api_key' },
      { pattern: /\b\.env\b/i, weight: 5, label: 'phrase:dotenv' },
      { pattern: /\bprivate\s+key\b/i, weight: 5, label: 'phrase:private_key' },
      { pattern: /\bwhat\s+(?:was\s+)?(?:leaked|exposed)\b/i, weight: 6, label: 'phrase:what_exposed' },
      { pattern: /\bhardcoded\s+(?:cred|secret|key|token)/i, weight: 5, label: 'phrase:hardcoded_cred' },
    ],
  },
  location: {
    exactKeywords: ['where', 'file', 'line', 'path'],
    shorthandTokens: ['location', 'located', 'spot'],
    phrases: [
      { pattern: /\bwhich\s+file\b/i, weight: 6, label: 'booster:which_file' },
      { pattern: /\bwhat\s+line\b/i, weight: 6, label: 'booster:what_line' },
      { pattern: /\bwhere\s+(?:is|are|was|were)\b/i, weight: 5, label: 'booster:where_is' },
    ],
  },
  egress: {
    exactKeywords: ['egress', 'network', 'outbound', 'domain', 'url', 'fetch', 'traffic', 'canary'],
    shorthandTokens: ['c2', 'exfil', 'exfiltration', 'beacon', 'callback', 'ip', 'socket', 'dns', 'webhook', 'host', 'hostname', 'port'],
    phrases: [
      { pattern: /\bphone\s+home\b/i, weight: 5, label: 'shorthand:phone_home' },
      { pattern: /\boutbound\s+(?:egress|network|traffic|call|request|domain|host)/i, weight: 5, label: 'phrase:outbound' },
      { pattern: /\bcontact(?:ed|ing)?\s+(?:external|outbound)/i, weight: 4, label: 'phrase:contacted' },
    ],
  },
  fix: {
    exactKeywords: ['fix', 'patch', 'remediation', 'solve', 'test', 'fail'],
    shorthandTokens: ['ci', 'red', 'broken', 'broke', 'stacktrace', 'stderr', 'traceback', 'crash', 'pytest', 'jest', 'vitest', 'mocha', 'squash'],
    phrases: [
      { pattern: /\bexit\s*(?:code\s*)?1\b/i, weight: 6, label: 'shorthand:exit_1' },
      { pattern: /\bexit\s+code\b/i, weight: 5, label: 'phrase:exit_code' },
      { pattern: /\bhow\s+(?:to|do\s+i|should\s+i|can\s+i)\s+(?:fix|remediate|solve|patch|replace)\b/i, weight: 6, label: 'booster:how_to_fix' },
      { pattern: /\bgive\s+me\s+the\s+code\b/i, weight: 6, label: 'booster:give_code' },
      { pattern: /\bwhat\s+should\s+i\s+replace\b/i, weight: 6, label: 'booster:replace_with' },
      { pattern: /\bwhy\s+(?:is|did)\s+(?:ci|the\s+test|tests|patch\s+tests?)\s+(?:red|fail|break|broken)/i, weight: 7, label: 'phrase:ci_red' },
      { pattern: /\b(?:test|tests)\s+(?:fail|failed|failing|error|output|log)/i, weight: 5, label: 'phrase:test_fail' },
    ],
  },
  exploit: {
    exactKeywords: ['exploit', 'risk', 'score', 'danger', 'impact', 'attack', 'severity'],
    shorthandTokens: ['hack', 'breach', 'compromise', 'vulnerable', 'vuln', 'vulnerability', 'abuse', 'steal'],
    phrases: [
      { pattern: /\bwhat\s+happens\s+if\b/i, weight: 6, label: 'booster:what_happens_if' },
      { pattern: /\bis\s+(?:this|it)\s+(?:actually\s+)?(?:dangerous|risky|exploitable)\b/i, weight: 7, label: 'booster:is_dangerous' },
      { pattern: /\bwhy\s+is\s+(?:that|this|it)\s+(?:risky|dangerous|bad|critical|high)\b/i, weight: 7, label: 'booster:why_risky' },
      { pattern: /\b(?:leak\s+user\s+data|get\s+(?:us\s+)?hacked|break\s+prod|blast\s+radius)\b/i, weight: 8, label: 'cluster:threat_matrix' },
      { pattern: /\brisk\s*(?:score|breakdown|contribution)/i, weight: 6, label: 'phrase:risk_score' },
    ],
  },
  approve: {
    exactKeywords: ['approve', 'merge', 'commit', 'push'],
    shorthandTokens: ['ship', 'lgtm', 'green', 'unblock', 'gate', 'ready', 'land'],
    phrases: [
      { pattern: /\bcan\s+i\s+(?:merge|ship|approve|land|push)\b/i, weight: 8, label: 'booster:can_i_merge' },
      { pattern: /\blgtm\s+ship\b/i, weight: 7, label: 'shorthand:lgtm_ship' },
      { pattern: /\bci\s+check\b/i, weight: 4, label: 'shorthand:ci_check' },
      { pattern: /\bwhat\s+is\s+(?:@?spriteguard\s+)?waiting\s+on\b/i, weight: 7, label: 'cluster:waiting_on' },
      { pattern: /\bwhy\s+can['’]?t\s+i\s+merge\b/i, weight: 7, label: 'cluster:cant_merge' },
      { pattern: /\bwhy\s+is\s+the\s+check\s+failing\b/i, weight: 6, label: 'cluster:check_failing' },
    ],
  },
  diff: {
    exactKeywords: ['diff', 'hunk'],
    shorthandTokens: ['before', 'after', 'edit', 'change'],
    phrases: [
      { pattern: /\bshow\s+(?:me\s+)?(?:the\s+)?(?:patch\s+)?diff\b/i, weight: 8, label: 'phrase:show_diff' },
      { pattern: /\bshow\s+(?:me\s+)?the\s+patch\b/i, weight: 7, label: 'phrase:show_patch' },
      { pattern: /\bwhat\s+did\s+you\s+(?:edit|change)\b/i, weight: 7, label: 'phrase:what_edited' },
      { pattern: /\bline\s+change/i, weight: 6, label: 'phrase:line_change' },
      { pattern: /\bbefore\s+and\s+after\b/i, weight: 6, label: 'phrase:before_after' },
    ],
  },
  evidence: {
    exactKeywords: ['evidence', 'snippet'],
    shorthandTokens: [],
    phrases: [
      { pattern: /\bwhat\s+does\s+the\s+code\s+look\s+like\b/i, weight: 9, label: 'phrase:code_look_like' },
      { pattern: /\bshow\s+(?:me\s+)?(?:the\s+)?(?:code|evidence|offending\s+line)\b/i, weight: 8, label: 'phrase:show_evidence' },
      { pattern: /\boffending\s+line\b/i, weight: 7, label: 'phrase:offending_line' },
    ],
  },
  metadata: {
    exactKeywords: ['sprite', 'sandbox', 'microvm', 'checkpoint', 'sha', 'branch'],
    shorthandTokens: ['vm', 'runtime', 'environment', 'duration', 'isolation'],
    phrases: [
      { pattern: /\bcommit\s+sha\b/i, weight: 7, label: 'phrase:commit_sha' },
      { pattern: /\bsandbox\s+(?:metadata|info|status|id|state)\b/i, weight: 7, label: 'phrase:sandbox_meta' },
      { pattern: /\bsprite\s+(?:id|status|state|lifecycle|checkpoint)\b/i, weight: 7, label: 'phrase:sprite_meta' },
    ],
  },
  false_positive: {
    exactKeywords: ['ignore', 'dismiss', 'suppress', 'override', 'whitelist', 'allowlist', 'skip'],
    shorthandTokens: ['intentional', 'anyway'],
    phrases: [
      { pattern: /\bfalse\s+positive\b/i, weight: 9, label: 'phrase:false_positive' },
      { pattern: /\bnot\s+a\s+secret\b/i, weight: 8, label: 'phrase:not_a_secret' },
      { pattern: /\bcan\s+i\s+(?:ignore|skip|dismiss|suppress|override|ship\s+anyway)\b/i, weight: 9, label: 'cluster:override' },
      { pattern: /\bship\s+anyway\b/i, weight: 9, label: 'cluster:ship_anyway' },
      { pattern: /\boverride\s+this\b/i, weight: 8, label: 'cluster:override_this' },
    ],
  },
  next_steps: {
    exactKeywords: ['checklist', 'instruction'],
    shorthandTokens: ['proceed'],
    phrases: [
      { pattern: /\bwhat\s+do\s+i\s+do\b/i, weight: 8, label: 'phrase:what_do_i_do' },
      { pattern: /\bnext\s+steps?\b/i, weight: 8, label: 'phrase:next_steps' },
      { pattern: /\bhow\s+to\s+proceed\b/i, weight: 8, label: 'phrase:how_to_proceed' },
      { pattern: /\baction\s+items?\b/i, weight: 8, label: 'phrase:action_items' },
      { pattern: /\bstep[\s-]by[\s-]step\b/i, weight: 7, label: 'phrase:step_by_step' },
    ],
  },
  draft: {
    exactKeywords: ['draft', 'slack', 'escalate', 'share'],
    shorthandTokens: ['comment', 'message'],
    phrases: [
      { pattern: /\bdraft\s+(?:a|an|the)?\s*(?:slack|pr|team|escalation|security)?/i, weight: 9, label: 'phrase:draft' },
      { pattern: /\bsummary\s+for\s+(?:my\s+)?team\b/i, weight: 9, label: 'phrase:team_summary' },
      { pattern: /\b(?:post|write|generate)\s+(?:a\s+)?(?:pr\s+)?(?:comment|slack|message)\b/i, weight: 8, label: 'phrase:post_comment' },
      { pattern: /\bslack\s+(?:summary|message|update|report)\b/i, weight: 9, label: 'phrase:slack_summary' },
    ],
  },
  quantitative: {
    exactKeywords: ['count', 'total'],
    shorthandTokens: [],
    phrases: [
      { pattern: /\bhow\s+many\b/i, weight: 10, label: 'booster:how_many' },
      { pattern: /\bnumber\s+of\b/i, weight: 8, label: 'booster:number_of' },
      { pattern: /\bseverity\s+breakdown\b/i, weight: 7, label: 'phrase:sev_breakdown' },
    ],
  },
  boolean: {
    exactKeywords: [],
    shorthandTokens: [],
    phrases: [
      { pattern: /\b(?:is\s+it|is\s+this)\s+(?:safe|clean|blocked|passing|ready)\b/i, weight: 9, label: 'booster:is_it_safe' },
      { pattern: /\bdid\s+(?:the\s+)?(?:patch\s+)?tests?\s+pass\b/i, weight: 9, label: 'booster:did_tests_pass' },
      { pattern: /\bis\s+there\s+a\s+(?:patch|fix)\b/i, weight: 9, label: 'booster:is_there_patch' },
      { pattern: /\b(?:are\s+there\s+)?any\s+(?:critical|high|secret|leaked|key|egress|c2|exfil\w*|beacon|callback|domain|outbound|finding|issue)/i, weight: 9, label: 'booster:are_there_any' },
      { pattern: /^\s*blocked\??\s*$/i, weight: 9, label: 'booster:blocked_only' },
    ],
  },
  comparison: {
    exactKeywords: ['worst', 'highest', 'biggest'],
    shorthandTokens: ['priority', 'top'],
    phrases: [
      { pattern: /\bmost\s+(?:severe|critical|dangerous|important)\b/i, weight: 9, label: 'phrase:most_severe' },
      { pattern: /\b(?:main|top|biggest|worst)\s+(?:issue|finding|risk|blocker|problem)\b/i, weight: 10, label: 'phrase:worst_issue' },
      { pattern: /\bwhat['’]?s\s+the\s+worst\b/i, weight: 10, label: 'phrase:whats_worst' },
      { pattern: /\bfix\s+first\b/i, weight: 9, label: 'phrase:fix_first' },
      { pattern: /\btop\s+priority\b/i, weight: 9, label: 'phrase:top_priority' },
    ],
  },
  full_report: {
    exactKeywords: [],
    shorthandTokens: [],
    phrases: [
      { pattern: /\bwalk\s+me\s+through\s+everything\b/i, weight: 12, label: 'cluster:walk_through' },
      { pattern: /\bfull\s+(?:breakdown|report|audit|analysis)\b/i, weight: 11, label: 'cluster:full_breakdown' },
      { pattern: /\bcomplete\s+(?:report|breakdown|audit)\b/i, weight: 11, label: 'cluster:complete_report' },
    ],
  },
  summary: {
    exactKeywords: ['tldr', 'overview'],
    shorthandTokens: [],
    phrases: [
      { pattern: /\bwhy\s+was\s+(?:this|the\s+pr)\s+flagged\b/i, weight: 10, label: 'phrase:why_flagged' },
      { pattern: /\bsummariz(?:e|ing)\s+(?:this|the\s+pr|the\s+audit|everything)\b/i, weight: 9, label: 'phrase:summarize' },
      { pattern: /\bgive\s+(?:me\s+)?(?:a\s+)?(?:quick\s+)?(?:summary|overview|tldr)\b/i, weight: 9, label: 'phrase:overview' },
    ],
  },
};

export function scoreIntents(nq: NormalizedQuery, entities: EntityResolution): ScoredIntent[] {
  const scores = new Map<IntentId, { score: number; reasons: string[] }>();
  const addScore = (intent: IntentId, pts: number, reason: string) => {
    const cur = scores.get(intent) ?? { score: 0, reasons: [] };
    cur.score += pts;
    cur.reasons.push(`${reason}(+${pts})`);
    scores.set(intent, cur);
  };

  // Evaluate exact keywords, shorthand, fuzzy keywords, and phrases per intent
  for (const intent of INTENT_TIE_ORDER) {
    const spec = INTENT_RULES[intent];
    const matchedKeywords = new Set<string>();

    for (const kw of spec.exactKeywords) {
      let bestMatch: 'exact' | 'fuzzy' | null = null;
      for (const tok of nq.stemmedTokens) {
        const m = fuzzyTokenMatch(tok, kw);
        if (m === 'exact') {
          bestMatch = 'exact';
          break;
        }
        if (m === 'fuzzy') bestMatch = 'fuzzy';
      }
      if (!bestMatch) {
        for (const tok of nq.identifierTokens) {
          const m = fuzzyTokenMatch(tok, kw);
          if (m === 'exact') {
            bestMatch = 'exact';
            break;
          }
          if (m === 'fuzzy') bestMatch = 'fuzzy';
        }
      }
      if (bestMatch === 'exact' && !matchedKeywords.has(kw)) {
        matchedKeywords.add(kw);
        addScore(intent, 5, `kw:${kw}`);
      } else if (bestMatch === 'fuzzy' && !matchedKeywords.has(kw)) {
        matchedKeywords.add(kw);
        addScore(intent, 3, `fuzzy:${kw}`);
      }
    }

    for (const sh of spec.shorthandTokens) {
      let hit = false;
      for (const tok of nq.stemmedTokens) {
        if (fuzzyTokenMatch(tok, sh)) {
          hit = true;
          break;
        }
      }
      if (!hit) {
        for (const tok of nq.tokens) {
          if (fuzzyTokenMatch(tok, sh)) {
            hit = true;
            break;
          }
        }
      }
      if (hit && !matchedKeywords.has(sh)) {
        matchedKeywords.add(sh);
        addScore(intent, 3, `shorthand:${sh}`);
      }
    }

    for (const p of spec.phrases) {
      if (p.pattern.test(nq.raw) || p.pattern.test(nq.cleaned)) {
        addScore(intent, p.weight, p.label);
      }
    }
  }

  // Cross-intent semantic cluster: "what is @spriteguard waiting on?" / "why is the check failing?"
  // boosts BOTH approve and fix so compound response surfaces eligibility + test diagnostics
  if (/\b(?:waiting\s+on|why\s+is\s+the\s+check\s+failing|why\s+can['’]?t\s+i\s+merge)\b/i.test(nq.raw)) {
    addScore('fix', 6, 'cluster:waiting_on_diag');
  }

  // Entity-first score boosts (+10 exact / +6 fuzzy)
  if (entities.isEntityScoped) {
    const entityBoost = entities.matchStrength === 'exact' ? 10 : 6;
    if (entities.requestedFailingTest) {
      addScore('fix', entityBoost, 'entity:failing_test');
    }
    if (entities.absentDomains.length > 0 || entities.matchedDomains.length > 0) {
      addScore('egress', entityBoost, 'entity:domain');
    }
    if (entities.matchedFiles.length > 0) {
      // Only let entity boost drive Location if no stronger action intent (fix/diff/evidence/exploit) was asked
      const actionIntents: IntentId[] = ['fix', 'diff', 'evidence', 'exploit', 'false_positive'];
      const hasExplicitAction = actionIntents.some((a) => (scores.get(a)?.score ?? 0) >= 5);
      if (!hasExplicitAction) {
        addScore('location', entityBoost, 'entity:file');
      }
    }
    if (entities.matchedFindings.length > 0 && entities.matchedFiles.length === 0 && entities.matchedDomains.length === 0) {
      const actionIntents: IntentId[] = ['fix', 'diff', 'evidence', 'exploit', 'location', 'false_positive', 'approve', 'boolean', 'metadata'];
      const hasExplicitAction = actionIntents.some((a) => (scores.get(a)?.score ?? 0) >= 5);
      if (!hasExplicitAction) {
        const allSecrets = entities.matchedFindings.every(isSecretFinding);
        const allEgress = entities.matchedFindings.every(isEgressFinding);
        if (allSecrets) addScore('secrets', entityBoost, 'entity:secret_finding');
        else if (allEgress) addScore('egress', entityBoost, 'entity:egress_finding');
        else addScore('exploit', entityBoost, 'entity:finding');
      }
    }
  }

  // Suppress redundant secondary intents when a specialized meta-intent clearly dominates
  if ((scores.get('full_report')?.score ?? 0) >= 10) {
    return [{ intent: 'full_report', score: scores.get('full_report')!.score, reasons: scores.get('full_report')!.reasons }];
  }
  if ((scores.get('draft')?.score ?? 0) >= 9) {
    return [{ intent: 'draft', score: scores.get('draft')!.score, reasons: scores.get('draft')!.reasons }];
  }
  if ((scores.get('false_positive')?.score ?? 0) >= 8) {
    return [{ intent: 'false_positive', score: scores.get('false_positive')!.score, reasons: scores.get('false_positive')!.reasons }];
  }
  if ((scores.get('comparison')?.score ?? 0) >= 9) {
    return [{ intent: 'comparison', score: scores.get('comparison')!.score, reasons: scores.get('comparison')!.reasons }];
  }
  if ((scores.get('quantitative')?.score ?? 0) >= 8) {
    return [{ intent: 'quantitative', score: scores.get('quantitative')!.score, reasons: scores.get('quantitative')!.reasons }];
  }
  if ((scores.get('summary')?.score ?? 0) >= 9 && !nq.hasCompoundJoiner) {
    return [{ intent: 'summary', score: scores.get('summary')!.score, reasons: scores.get('summary')!.reasons }];
  }

  // If "did the patch tests pass?" is asked standalone (not compound), let boolean win cleanly
  if ((scores.get('boolean')?.score ?? 0) >= 8 && !nq.hasCompoundJoiner) {
    // Keep approve ahead when user explicitly asks "can i merge?" / "can i approve?"
    const approveScore = scores.get('approve')?.score ?? 0;
    const boolScore = scores.get('boolean')?.score ?? 0;
    if (approveScore < boolScore) {
      return [{ intent: 'boolean', score: boolScore, reasons: scores.get('boolean')!.reasons }];
    }
  }

  const ranked: ScoredIntent[] = [...scores.entries()]
    .filter(([, v]) => v.score > 0)
    .map(([intent, v]) => ({ intent, score: v.score, reasons: v.reasons }))
    .sort((a, b) => b.score - a.score || TIE_RANK[a.intent] - TIE_RANK[b.intent]);

  return ranked;
}

export function selectWinningIntents(
  ranked: readonly ScoredIntent[],
  nq: NormalizedQuery,
): IntentId[] {
  const leader = ranked[0];
  if (!leader || leader.score < 4) return [];

  const runnerUp = ranked[1];
  if (!runnerUp) return [leader.intent];

  // Compound query detection:
  // 1) Explicit "and"/"also" with multiple intents scoring >= 5
  // 2) Or multiple intents scoring >= 6 within 3 points of the leader (excluding redundant pairs)
  const isRedundantPair = (a: IntentId, b: IntentId): boolean => {
    const pair = [a, b].sort().join(':');
    return (
      pair === 'boolean:egress' ||
      pair === 'boolean:secrets' ||
      pair === 'boolean:fix' ||
      pair === 'approve:boolean' ||
      pair === 'exploit:summary' ||
      pair === 'location:secrets' && !nq.hasCompoundJoiner
    );
  };

  const candidates = ranked.filter((r, idx) => {
    if (idx === 0) return true;
    if (isRedundantPair(leader.intent, r.intent)) return false;
    if (nq.hasCompoundJoiner && r.score >= 5) return true;
    if (r.score >= 6 && leader.score - r.score <= 3) return true;
    return false;
  });

  if (candidates.length >= 2) {
    return candidates.slice(0, 3).map((c) => c.intent);
  }

  return [leader.intent];
}
