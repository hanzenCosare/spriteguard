import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Octokit } from '@octokit/rest';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { loadConfig, type AppConfig } from './config.js';
import { createStore, type Store } from './db/client.js';
import { createCleanPrFixture, createVulnerablePrFixture, registerDemoMaintainers } from './demoFixtures.js';
import {
  buildGitDiff,
  createGitHubConnectors,
  fakeSha,
  LocalGitHubSimulator,
  LocalReadOnlyConnector,
  LocalWriteConnector,
  splitRepo,
  type GitHubConnectors,
  type GitHubWriteConnector,
  type ReadOnlyGitHubConnector,
  type RepoPermission,
  type SourceDelivery,
} from './fly/githubConnector.js';
import { createSpriteManager, type SpriteManager } from './fly/spriteManager.js';
import { WebhookHandler } from './github/webhookHandler.js';
import { createLogger, type Logger } from './logger.js';
import { AuditOrchestrator, TrustedPublisher } from './orchestrator.js';
import { OpusAuditor } from './scanner/opusAuditor.js';
import type { CommitPatch, PatchRecord, PrContext, ScanRecord, ScanStatus } from './types.js';

declare module 'fastify' {
  interface FastifyRequest {
    rawBody?: Buffer;
  }
}

export interface SpriteGuardApp {
  app: FastifyInstance;
  config: AppConfig;
  log: Logger;
  store: Store;
  spriteManager: SpriteManager;
  connectors: GitHubConnectors;
  orchestrator: AuditOrchestrator;
  webhookHandler: WebhookHandler;
  close: () => Promise<void>;
}

function checkDashboardAuth(req: FastifyRequest, reply: FastifyReply, token: string | undefined): boolean {
  if (!token) return true;
  const auth = req.headers.authorization;
  const queryToken = (req.query as { token?: string } | undefined)?.token;
  if (auth === `Bearer ${token}` || queryToken === token) return true;
  void reply.code(401).send({ error: 'Unauthorized: invalid or missing DASHBOARD_TOKEN' });
  return false;
}

export interface ParsedGitHubPrInput {
  owner: string;
  repo: string;
  repoFullName: string;
  prNumber?: number;
}

const VALID_GH_SEGMENT = /^[A-Za-z0-9_.-]+$/;

export function parseGitHubPrUrl(input: string): ParsedGitHubPrInput | null {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 512 || trimmed.includes('..')) return null;

  const sanitizeRepo = (rawOwner: string, rawRepo: string, pr?: number): ParsedGitHubPrInput | null => {
    const owner = rawOwner.trim();
    const repo = rawRepo.trim().replace(/\.git$/i, '');
    if (!owner || !repo || owner === '.' || repo === '.') return null;
    if (!VALID_GH_SEGMENT.test(owner) || !VALID_GH_SEGMENT.test(repo)) return null;
    const out: ParsedGitHubPrInput = { owner, repo, repoFullName: `${owner}/${repo}` };
    if (pr !== undefined) {
      if (!Number.isInteger(pr) || pr <= 0) return null;
      out.prNumber = pr;
    }
    return out;
  };

  if (!trimmed.includes('://') && !trimmed.startsWith('github.com/')) {
    const parts = trimmed.replace(/^\/+|\/+$/g, '').split('/');
    if (parts.length === 2 && parts[0] && parts[1]) {
      return sanitizeRepo(parts[0], parts[1]);
    }
    return null;
  }

  try {
    const normalized = trimmed.startsWith('github.com/') ? `https://${trimmed}` : trimmed;
    const u = new URL(normalized);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    const host = u.hostname.toLowerCase();
    if (host !== 'github.com' && host !== 'www.github.com') return null;
    const segs = u.pathname.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
    if (segs.length < 2 || !segs[0] || !segs[1]) return null;
    if (segs.length === 2 || (segs.length === 3 && segs[2] === 'pulls')) {
      return sanitizeRepo(segs[0], segs[1]);
    }
    if (segs.length >= 4 && segs[2] === 'pull' && /^\d+$/.test(segs[3] ?? '')) {
      return sanitizeRepo(segs[0], segs[1], Number.parseInt(segs[3]!, 10));
    }
    return null;
  } catch {
    return null;
  }
}

function createPublicReadOnlyConnector(apiUrl: string, token: string | undefined): ReadOnlyGitHubConnector {
  const gh = new Octokit({
    ...(token ? { auth: token } : {}),
    baseUrl: apiUrl,
    userAgent: 'spriteguard',
  });

  const httpStatus = (err: unknown): number | undefined =>
    typeof err === 'object' && err !== null && 'status' in err ? Number((err as { status: unknown }).status) : undefined;

  return {
    mode: 'token',
    rememberInstallation(): void {},
    async getPullRequest(repoFullName: string, prNumber: number): Promise<PrContext> {
      const { owner, repo } = splitRepo(repoFullName);
      const { data } = await gh.pulls.get({ owner, repo, pull_number: prNumber });
      const headRepo = data.head.repo;
      return {
        owner,
        repo,
        repoFullName,
        number: data.number,
        title: data.title,
        body: data.body ?? '',
        author: data.user?.login ?? 'unknown',
        headSha: data.head.sha,
        headRef: data.head.ref,
        headRepoFullName: headRepo?.full_name ?? repoFullName,
        headCloneUrl: headRepo?.clone_url ?? `https://github.com/${repoFullName}.git`,
        baseRef: data.base.ref,
        isFork: Boolean(headRepo && headRepo.full_name !== data.base.repo.full_name),
        isPrivate: data.base.repo.private,
        maintainerCanModify: data.maintainer_can_modify,
        state: data.state === 'open' ? 'open' : 'closed',
      };
    },
    async getPullRequestDiff(repoFullName: string, prNumber: number): Promise<string> {
      const { owner, repo } = splitRepo(repoFullName);
      try {
        const res = await gh.pulls.get({ owner, repo, pull_number: prNumber, mediaType: { format: 'diff' } });
        return res.data as unknown as string;
      } catch (err) {
        if (httpStatus(err) !== 406 && httpStatus(err) !== 422) throw err;
        const files = await gh.paginate(gh.pulls.listFiles, { owner, repo, pull_number: prNumber, per_page: 100 });
        return files
          .filter((f) => f.patch)
          .map((f) => `diff --git a/${f.filename} b/${f.filename}\n--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch}`)
          .join('\n');
      }
    },
    async listCommitPatches(repoFullName: string, prNumber: number, maxCommits = 30): Promise<CommitPatch[]> {
      const { owner, repo } = splitRepo(repoFullName);
      const commits = await gh.paginate(gh.pulls.listCommits, { owner, repo, pull_number: prNumber, per_page: 100 });
      const recent = commits.slice(-maxCommits);
      const out: CommitPatch[] = [];
      for (const c of recent) {
        const { data } = await gh.repos.getCommit({ owner, repo, ref: c.sha });
        out.push({
          sha: c.sha,
          message: c.commit.message,
          author: c.author?.login ?? c.commit.author?.name ?? 'unknown',
          files: (data.files ?? []).map((f) => ({ filename: f.filename, patch: f.patch ?? '' })),
        });
      }
      return out;
    },
    async getFileContent(repoFullName: string, path: string, ref: string): Promise<string | null> {
      const { owner, repo } = splitRepo(repoFullName);
      try {
        const { data } = await gh.repos.getContent({ owner, repo, path, ref });
        if (Array.isArray(data) || data.type !== 'file') return null;
        if ('content' in data && data.content) return Buffer.from(data.content, 'base64').toString('utf8');
        const blob = await gh.git.getBlob({ owner, repo, file_sha: data.sha });
        return Buffer.from(blob.data.content, 'base64').toString('utf8');
      } catch (err) {
        if (httpStatus(err) === 404) return null;
        throw err;
      }
    },
    async getRepoPermission(): Promise<RepoPermission> {
      return 'read';
    },
    async getSourceDelivery(pr: PrContext): Promise<SourceDelivery> {
      return { kind: 'git', cloneUrl: pr.headCloneUrl, sha: pr.headSha };
    },
  };
}

function createNoopWriteConnector(): GitHubWriteConnector {
  return {
    mode: 'token',
    rememberInstallation(): void {},
    async postComment(): Promise<number> {
      return 0;
    },
    async updateComment(): Promise<void> {},
    async addReaction(): Promise<void> {},
    async commitFiles(): Promise<string> {
      throw new Error('Ad-hoc public URL scans are read-only and cannot commit to external repositories.');
    },
  };
}

export async function createApp(customConfig?: AppConfig): Promise<SpriteGuardApp> {
  const config = customConfig ?? loadConfig();
  const log = createLogger(config.logLevel);

  const { store, embeddings } = createStore(config, log);
  await store.init();

  const spriteManager = createSpriteManager(
    {
      localSandboxMode: config.localSandboxMode,
      token: config.sprites.token,
      apiUrl: config.sprites.apiUrl,
      prefix: config.sprites.namePrefix,
    },
    log.child({ module: 'sprites' }),
  );

  const connectors = createGitHubConnectors(config, log);
  const auditor = new OpusAuditor(config.llm, log.child({ module: 'opus' }));
  const publisher = new TrustedPublisher(connectors.write);
  const orchestrator = new AuditOrchestrator(
    config,
    store,
    embeddings,
    spriteManager,
    connectors.read,
    publisher,
    auditor,
    log.child({ module: 'orchestrator' }),
  );

  const webhookHandler = new WebhookHandler(
    config.github.webhookSecret,
    config.github.botLogin,
    connectors.read,
    orchestrator,
    log.child({ module: 'webhook' }),
  );

  const playgroundEnabled =
    config.localSandboxMode ||
    ['1', 'true', 'yes', 'on'].includes((process.env.ENABLE_PUBLIC_PLAYGROUND ?? '').trim().toLowerCase());

  const app = Fastify({
    logger: false,
    bodyLimit: 10 * 1024 * 1024,
  });

  // Preserve exact raw bytes for GitHub X-Hub-Signature-256 HMAC verification
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    req.rawBody = buf;
    const text = buf.toString('utf8').trim();
    if (!text) {
      done(null, {});
      return;
    }
    try {
      done(null, JSON.parse(text));
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  const dashboardPath = fileURLToPath(new URL('./ui/dashboard.html', import.meta.url));
  let cachedDashboardHtml: string | null = null;

  app.get('/', async (_req, reply) => {
    if (!cachedDashboardHtml || config.env !== 'production') {
      cachedDashboardHtml = await readFile(dashboardPath, 'utf8');
    }
    return reply.type('text/html; charset=utf-8').send(cachedDashboardHtml);
  });

  const healthHandler = async (_req: FastifyRequest, reply: FastifyReply) => {
    const dbHealthy = await store.ping();
    const statusCode = dbHealthy ? 200 : 503;
    return reply.code(statusCode).send({
      status: dbHealthy ? 'ok' : 'degraded',
      service: 'spriteguard',
      mode: config.localSandboxMode ? 'local-sandbox' : 'production',
      playgroundEnabled,
      store: store.backend,
      dbHealthy,
      spriteDriver: spriteManager.driver.kind,
      githubMode: connectors.read.mode,
      aiEnabled: auditor.hasAi,
      provider: auditor.provider,
      model: auditor.model,
      timestamp: new Date().toISOString(),
    });
  };

  app.get('/health', healthHandler);
  app.get('/api/health', healthHandler);

  app.post('/webhook', async (req, reply) => {
    const event = typeof req.headers['x-github-event'] === 'string' ? req.headers['x-github-event'] : undefined;
    const deliveryId =
      typeof req.headers['x-github-delivery'] === 'string' ? req.headers['x-github-delivery'] : undefined;
    const signature256 =
      typeof req.headers['x-hub-signature-256'] === 'string' ? req.headers['x-hub-signature-256'] : undefined;
    const rawBody = req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), 'utf8');

    const result = await webhookHandler.handle({
      event,
      deliveryId,
      signature256,
      rawBody,
      payload: req.body,
    });
    return reply.code(result.statusCode).send(result);
  });

  app.get('/api/scans', async (req, reply) => {
    if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
    const q = req.query as { limit?: string; repo?: string; status?: ScanStatus } | undefined;
    const limit = q?.limit ? Math.min(200, Math.max(1, Number.parseInt(q.limit, 10) || 50)) : 50;

    const [stats, rawScans] = await Promise.all([
      store.getStats(),
      store.listScans({
        limit,
        ...(q?.repo ? { repo: q.repo } : {}),
        ...(q?.status ? { status: q.status } : {}),
      }),
    ]);

    const scans: Array<ScanRecord & { patch: Omit<PatchRecord, 'files'> | null }> = await Promise.all(
      rawScans.map(async (scan) => {
        const patch = await store.getPatch(scan.id);
        if (!patch) return { ...scan, patch: null };
        const { files: _files, ...publicPatch } = patch;
        return { ...scan, patch: publicPatch };
      }),
    );

    return reply.send({
      mode: config.localSandboxMode ? 'local-sandbox' : 'production',
      playgroundEnabled,
      storeBackend: store.backend,
      spriteDriver: spriteManager.driver.kind,
      provider: auditor.provider,
      model: auditor.model,
      stats,
      scans,
    });
  });

  app.get('/api/scans/:id', async (req, reply) => {
    if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
    const { id } = req.params as { id: string };
    const scan = await store.getScan(id);
    if (!scan) return reply.code(404).send({ error: 'Scan not found' });
    const patch = await store.getPatch(scan.id);
    const timeline = connectors.simulator
      ? connectors.simulator.getTimeline(scan.repoFullName, scan.prNumber)
      : [];
    return reply.send({ scan, patch, timeline });
  });

  const publicReadConnector = createPublicReadOnlyConnector(config.github.apiUrl, config.github.readToken);
  const publicOrchestrator = new AuditOrchestrator(
    config,
    store,
    embeddings,
    spriteManager,
    publicReadConnector,
    new TrustedPublisher(createNoopWriteConnector()),
    auditor,
    log.child({ module: 'public-url-orchestrator' }),
  );

  // @spriteguard Q&A for ANY persisted scan (live GitHub PRs and Playground runs)
  app.post('/api/scans/:id/ask', async (req, reply) => {
    if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { asker?: string; question?: string };
    const scan = await store.getScan(id);
    if (!scan) return reply.code(404).send({ error: 'Scan not found' });

    const question = typeof body.question === 'string' ? body.question.trim() : '';
    if (!question) return reply.code(400).send({ error: 'question is required' });
    if (question.length > 2000) return reply.code(400).send({ error: 'question is too long (max 2000 chars)' });

    const patch = await store.getPatch(scan.id);
    const qVec = await embeddings.embed(question);
    const relatedIncidents = await store.searchSimilarFindings(scan.repoFullName, qVec, {
      limit: 5,
      excludeScanId: scan.id,
      minSimilarity: 0.25,
    });

    const answer = await auditor.answerQuestion({
      scan,
      report: scan.report,
      patch,
      relatedIncidents,
      question,
      asker: body.asker?.trim() || 'dashboard-user',
    });

    return reply.send({
      ok: true,
      answer,
      provider: auditor.provider,
      model: auditor.model,
      usedAi: auditor.hasAi,
    });
  });

  // On-demand public GitHub PR / repo scanner
  app.post('/api/github/audit-url', async (req, reply) => {
    if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
    const body = (req.body ?? {}) as { url?: string };
    const parsed = parseGitHubPrUrl(typeof body.url === 'string' ? body.url : '');
    if (!parsed) {
      return reply.code(400).send({
        error: 'Enter a valid GitHub PR URL (https://github.com/owner/repo/pull/123) or repository (owner/repo).',
      });
    }

    const gh = new Octokit({
      ...(config.github.readToken ? { auth: config.github.readToken } : {}),
      baseUrl: config.github.apiUrl,
      userAgent: 'spriteguard',
    });

    try {
      let prNumber = parsed.prNumber;
      if (prNumber === undefined) {
        const { data: openPrs } = await gh.pulls.list({
          owner: parsed.owner,
          repo: parsed.repo,
          state: 'open',
          sort: 'updated',
          direction: 'desc',
          per_page: 1,
        });
        const latest = openPrs[0];
        if (!latest) {
          return reply.code(404).send({ error: `No open pull requests found in ${parsed.repoFullName}.` });
        }
        prNumber = latest.number;
      }

      const scan = await publicOrchestrator.runPullRequestAudit(parsed.repoFullName, prNumber);
      const patch = await store.getPatch(scan.id);
      return reply.code(201).send({ scan, patch });
    } catch (err) {
      const status =
        typeof err === 'object' && err !== null && 'status' in err ? Number((err as { status: unknown }).status) : undefined;
      const msg = err instanceof Error ? err.message : String(err);
      if (status === 404) {
        return reply.code(404).send({ error: `GitHub repository or pull request not found (or private): ${parsed.repoFullName}` });
      }
      if (status === 403 || status === 429) {
        return reply.code(429).send({ error: `GitHub API rate limit or access denied: ${msg}` });
      }
      return reply.code(502).send({ error: `Failed to audit GitHub PR: ${msg}` });
    }
  });

  const simInstance = playgroundEnabled ? (connectors.simulator ?? new LocalGitHubSimulator(config.github.botLogin)) : null;
  const playgroundOrchestratorInstance = simInstance
    ? connectors.simulator
      ? orchestrator
      : new AuditOrchestrator(
          config,
          store,
          embeddings,
          spriteManager,
          new LocalReadOnlyConnector(simInstance),
          new TrustedPublisher(new LocalWriteConnector(simInstance)),
          auditor,
          log.child({ module: 'playground-orchestrator' }),
        )
    : null;

  app.post('/api/scans/:id/rescan', async (req, reply) => {
    if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
    const { id } = req.params as { id: string };
    const existing = await store.getScan(id);
    if (!existing) return reply.code(404).send({ error: 'Scan not found' });

    if (simInstance && playgroundOrchestratorInstance) {
      let inSim = false;
      try {
        simInstance.getPullRequest(existing.repoFullName, existing.prNumber);
        inSim = true;
      } catch {
        inSim = false;
      }
      if (inSim) {
        const scan = await playgroundOrchestratorInstance.runPullRequestAudit(existing.repoFullName, existing.prNumber);
        const patch = await store.getPatch(scan.id);
        return reply.code(201).send({ scan, patch });
      }
    }

    if (connectors.read.mode !== 'local') {
      const queued = orchestrator.enqueuePullRequestAudit(existing.repoFullName, existing.prNumber);
      return reply.code(202).send({
        queued: queued.accepted,
        repoFullName: existing.repoFullName,
        prNumber: existing.prNumber,
      });
    }

    const scan = await publicOrchestrator.runPullRequestAudit(existing.repoFullName, existing.prNumber);
    const patch = await store.getPatch(scan.id);
    return reply.code(201).send({ scan, patch });
  });

  // Local Sandbox / Public Playground interactive endpoints
  if (playgroundEnabled && simInstance && playgroundOrchestratorInstance) {
    const sim = simInstance;
    const playgroundOrchestrator = playgroundOrchestratorInstance;

    app.post('/api/demo/trigger', async (req, reply) => {
      if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
      const body = (req.body ?? {}) as { kind?: 'vulnerable' | 'clean'; repoFullName?: string };
      const kind = body.kind === 'clean' ? 'clean' : 'vulnerable';
      const pr =
        kind === 'clean'
          ? createCleanPrFixture(sim, { ...(body.repoFullName ? { repoFullName: body.repoFullName } : {}) })
          : createVulnerablePrFixture(sim, { ...(body.repoFullName ? { repoFullName: body.repoFullName } : {}) });

      const scan = await playgroundOrchestrator.runPullRequestAudit(pr.repoFullName, pr.number);
      const patch = await store.getPatch(scan.id);
      const timeline = sim.getTimeline(pr.repoFullName, pr.number);
      return reply.code(201).send({ scan, patch, timeline });
    });

    app.post('/api/demo/custom', async (req, reply) => {
      if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
      const body = (req.body ?? {}) as {
        title?: string;
        filename?: string;
        code?: string;
        repoFullName?: string;
      };

      const rawCode = typeof body.code === 'string' ? body.code : '';
      if (!rawCode.trim()) {
        return reply.code(400).send({ error: 'code snippet is required' });
      }
      if (rawCode.length > 100_000) {
        return reply.code(400).send({ error: 'code snippet exceeds 100KB limit' });
      }

      const rawFile = (typeof body.filename === 'string' ? body.filename : 'src/submission.mjs')
        .replace(/^\.\//, '')
        .replace(/\\/g, '/')
        .trim();
      const parts = rawFile.split('/');
      if (!rawFile || rawFile.startsWith('/') || parts.some((p) => !p || p === '.' || p === '..') || parts[0] === '.git') {
        return reply.code(400).send({ error: 'filename must be a safe relative repository path' });
      }

      const repoFullName =
        typeof body.repoFullName === 'string' && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(body.repoFullName.trim())
          ? body.repoFullName.trim()
          : 'playground/custom-sandbox';
      const title =
        (typeof body.title === 'string' && body.title.trim().slice(0, 140)) ||
        `audit(${rawFile}): custom sandbox submission`;

      // If user pasted a unified diff, extract added/context lines as the file body
      const isDiffInput = /^diff --git /m.test(rawCode) || /^@@ -\d+/m.test(rawCode);
      const fileContent = isDiffInput
        ? rawCode
            .split(/\r?\n/)
            .filter((l) => !l.startsWith('diff --git ') && !l.startsWith('--- ') && !l.startsWith('+++ ') && !l.startsWith('@@') && !l.startsWith('-'))
            .map((l) => (l.startsWith('+') || l.startsWith(' ') ? l.slice(1) : l))
            .join('\n')
        : rawCode;

      registerDemoMaintainers(sim, repoFullName);
      const number = sim.nextPrNumber(repoFullName);
      const isRunnableJs = /\.(?:mjs|js)$/.test(rawFile);

      const baseFiles: Record<string, string> = {
        'package.json': JSON.stringify(
          {
            name: 'custom-sandbox',
            version: '1.0.0',
            type: 'module',
            scripts: isRunnableJs ? { test: 'node --test test/smoke.test.mjs' } : {},
          },
          null,
          2,
        ),
        '.gitignore': 'node_modules/\n',
      };

      const headFiles: Record<string, string> = {
        ...baseFiles,
        [rawFile]: fileContent.endsWith('\n') ? fileContent : `${fileContent}\n`,
      };

      if (isRunnableJs) {
        headFiles['test/smoke.test.mjs'] = [
          'import test from "node:test";',
          'import assert from "node:assert/strict";',
          'test("loads custom module without fatal crash", async () => {',
          '  try {',
          `    const mod = await import(${JSON.stringify(`../${rawFile}`)});`,
          '    for (const val of Object.values(mod)) {',
          '      if (typeof val === "function" && val.length === 0) {',
          '        await Promise.resolve(val()).catch(() => {});',
          '      }',
          '    }',
          '  } catch {}',
          '  assert.ok(true);',
          '});',
          '',
        ].join('\n');
      }

      const headSha = fakeSha(`${repoFullName}#${number}:${rawFile}:${Date.now()}`);
      const diffText = buildGitDiff(baseFiles, headFiles);
      sim.upsertPullRequest({
        repoFullName,
        number,
        title,
        body: `Custom code audit submitted from SpriteGuard Playground for \`${rawFile}\`.`,
        author: 'sandbox-user',
        baseRef: 'main',
        headRef: `sandbox/custom-${number}`,
        headSha,
        baseFiles,
        headFiles,
        commits: [
          {
            sha: headSha,
            message: title,
            author: 'sandbox-user',
            files: [{ filename: rawFile, patch: diffText }],
          },
        ],
        state: 'open',
      });

      const scan = await playgroundOrchestrator.runPullRequestAudit(repoFullName, number);
      const patch = await store.getPatch(scan.id);
      const timeline = sim.getTimeline(repoFullName, number);
      return reply.code(201).send({ scan, patch, timeline });
    });

    app.post('/api/demo/scans/:id/approve', async (req, reply) => {
      if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
      const { id } = req.params as { id: string };
      const body = (req.body ?? {}) as { approver?: string };
      const scan = await store.getScan(id);
      if (!scan) return reply.code(404).send({ error: 'Scan not found' });
      const approver = body.approver?.trim() || 'alice-maintainer';
      const outcome = await playgroundOrchestrator.handleApproval(scan.repoFullName, scan.prNumber, approver);
      return reply.code(outcome.ok ? 200 : 400).send(outcome);
    });

    app.post('/api/demo/scans/:id/ask', async (req, reply) => {
      if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
      const { id } = req.params as { id: string };
      const body = (req.body ?? {}) as { asker?: string; question?: string };
      const scan = await store.getScan(id);
      if (!scan) return reply.code(404).send({ error: 'Scan not found' });
      const question = body.question?.trim();
      if (!question) return reply.code(400).send({ error: 'question is required' });
      const outcome = await playgroundOrchestrator.handleQuestion(
        scan.repoFullName,
        scan.prNumber,
        body.asker?.trim() || 'alice-maintainer',
        question,
      );
      return reply.send(outcome);
    });

    app.get('/api/demo/timeline', async (req, reply) => {
      if (!checkDashboardAuth(req, reply, config.dashboardToken)) return;
      const q = req.query as { repo?: string; pr?: string } | undefined;
      const prNum = q?.pr ? Number.parseInt(q.pr, 10) : undefined;
      return reply.send({
        timeline: sim.getTimeline(q?.repo, Number.isFinite(prNum) ? prNum : undefined),
      });
    });
  }

  const close = async (): Promise<void> => {
    orchestrator.stopReaper();
    await app.close();
    await store.close();
  };

  return {
    app,
    config,
    log,
    store,
    spriteManager,
    connectors,
    orchestrator,
    webhookHandler,
    close,
  };
}

const isEntrypoint = Boolean(
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]),
);

if (isEntrypoint) {
  const sg = await createApp();
  sg.orchestrator.startReaper();

  const shutdown = async (signal: string) => {
    sg.log.info({ signal }, 'shutting down SpriteGuard');
    await sg.close();
    process.exit(0);
  };
  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });

  await sg.app.listen({ host: sg.config.host, port: sg.config.port });
  sg.log.info(
    {
      host: sg.config.host,
      port: sg.config.port,
      mode: sg.config.localSandboxMode ? 'local-sandbox' : 'production',
      store: sg.store.backend,
      spriteDriver: sg.spriteManager.driver.kind,
    },
    'SpriteGuard server listening',
  );
}
