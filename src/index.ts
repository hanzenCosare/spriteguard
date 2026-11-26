import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  type GitHubConnectors,
} from './fly/githubConnector.js';
import { createSpriteManager, type SpriteManager } from './fly/spriteManager.js';
import { WebhookHandler } from './github/webhookHandler.js';
import { createLogger, type Logger } from './logger.js';
import { AuditOrchestrator, TrustedPublisher } from './orchestrator.js';
import { OpusAuditor } from './scanner/opusAuditor.js';
import type { PatchRecord, ScanRecord, ScanStatus } from './types.js';

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

  app.get('/health', async (_req, reply) => {
    const dbHealthy = await store.ping();
    const statusCode = dbHealthy ? 200 : 503;
    return reply.code(statusCode).send({
      status: dbHealthy ? 'ok' : 'degraded',
      service: 'spriteguard',
      mode: config.localSandboxMode ? 'local-sandbox' : 'production',
      store: store.backend,
      dbHealthy,
      spriteDriver: spriteManager.driver.kind,
      githubMode: connectors.read.mode,
      aiEnabled: auditor.hasAi,
      provider: auditor.provider,
      model: auditor.model,
      timestamp: new Date().toISOString(),
    });
  });

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

  // Local Sandbox / Public Playground interactive endpoints
  if (playgroundEnabled) {
    const sim = connectors.simulator ?? new LocalGitHubSimulator(config.github.botLogin);
    const playgroundOrchestrator = connectors.simulator
      ? orchestrator
      : new AuditOrchestrator(
          config,
          store,
          embeddings,
          spriteManager,
          new LocalReadOnlyConnector(sim),
          new TrustedPublisher(new LocalWriteConnector(sim)),
          auditor,
          log.child({ module: 'playground-orchestrator' }),
        );

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
