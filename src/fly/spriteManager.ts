import { spawn } from 'node:child_process';
import { cp, mkdir, rm, writeFile, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { APIError, ExecError, SpritesClient } from '@fly/sprites';
import type { Logger } from '../logger.js';
import type { SpriteState } from '../types.js';

/**
 * Fly.io Sprites lifecycle wrapper.
 *
 * Two interchangeable drivers implement {@link SpriteDriver}:
 *  • {@link SpritesApiDriver}  — production: hardware-isolated Firecracker microVMs via the official
 *    `@fly/sprites` SDK (create, exec, filesystem, checkpoint/restore, network policy, destroy).
 *  • {@link LocalSandboxDriver} — LOCAL_SANDBOX_MODE: a scratch directory + child processes so the whole
 *    pipeline can be demoed on a laptop. It provides NO isolation and is only used for trusted fixtures
 *    unless LOCAL_ALLOW_UNTRUSTED_EXEC=true.
 */

export interface SpriteExecOptions {
  timeoutMs?: number;
  env?: Record<string, string>;
  cwd?: string;
  maxOutputBytes?: number;
}

export interface SpriteExecResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export interface SpritePaths {
  root: string;
  repo: string;
  tools: string;
}

export interface SpriteDriver {
  readonly kind: 'local-sandbox' | 'fly-sprites';
  readonly isolated: boolean;
  paths(name: string): SpritePaths;
  create(name: string, labels: string[]): Promise<void>;
  exists(name: string): Promise<boolean>;
  exec(name: string, script: string, opts?: SpriteExecOptions): Promise<SpriteExecResult>;
  writeFile(name: string, path: string, data: string | Buffer, mode?: number): Promise<void>;
  checkpoint(name: string, comment: string): Promise<string>;
  restore(name: string, checkpointId: string): Promise<void>;
  setNetworkPolicy(name: string, allowDomains: string[]): Promise<boolean>;
  sleep(name: string): Promise<void>;
  wake(name: string): Promise<void>;
  destroy(name: string): Promise<void>;
}

const DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

function truncateOutput(value: string, max: number): string {
  if (Buffer.byteLength(value) <= max) return value;
  const half = Math.floor(max / 2);
  return `${value.slice(0, half)}\n…[spriteguard: output truncated]…\n${value.slice(-half)}`;
}

function asString(v: string | Buffer | undefined): string {
  if (v === undefined) return '';
  return typeof v === 'string' ? v : v.toString('utf8');
}

/* -------------------------------------------------------------------------------------------------
 * Production driver — Fly.io Sprites
 * -----------------------------------------------------------------------------------------------*/

export class SpritesApiDriver implements SpriteDriver {
  readonly kind = 'fly-sprites' as const;
  readonly isolated = true;
  private readonly client: SpritesClient;

  constructor(
    token: string,
    baseURL: string,
    private readonly log: Logger,
  ) {
    this.client = new SpritesClient(token, { baseURL, timeout: 60_000 });
  }

  paths(_name: string): SpritePaths {
    const root = '/home/sprite/spriteguard';
    return { root, repo: `${root}/repo`, tools: `${root}/tools` };
  }

  async create(name: string, labels: string[]): Promise<void> {
    for (let attempt = 1; attempt <= 4; attempt++) {
      try {
        await this.client.createSprite(name, { labels, waitForCapacity: true });
        return;
      } catch (err) {
        if (err instanceof APIError) {
          if (err.statusCode === 409) return; // already exists — idempotent
          if (err.isRateLimitError() && attempt < 4) {
            const wait = (err.getRetryAfterSeconds() ?? 5 * attempt) * 1000;
            this.log.warn({ name, wait }, 'sprite creation rate limited; retrying');
            await delay(wait);
            continue;
          }
        }
        throw err;
      }
    }
  }

  async exists(name: string): Promise<boolean> {
    try {
      await this.client.getSprite(name);
      return true;
    } catch (err) {
      if (err instanceof APIError && err.statusCode === 404) return false;
      throw err;
    }
  }

  async exec(name: string, script: string, opts: SpriteExecOptions = {}): Promise<SpriteExecResult> {
    const sprite = this.client.sprite(name);
    const started = Date.now();
    const maxOutput = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT;
    try {
      const execOpts: Parameters<typeof sprite.execFile>[2] = {
        timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: maxOutput * 2,
        encoding: 'utf8',
      };
      if (opts.cwd) execOpts.cwd = opts.cwd;
      if (opts.env) execOpts.env = opts.env;
      const res = await sprite.execFile('bash', ['-c', script], execOpts);
      return {
        exitCode: res.exitCode,
        stdout: truncateOutput(asString(res.stdout), maxOutput),
        stderr: truncateOutput(asString(res.stderr), maxOutput),
        durationMs: Date.now() - started,
        timedOut: false,
      };
    } catch (err) {
      if (err instanceof ExecError) {
        return {
          exitCode: err.exitCode,
          stdout: truncateOutput(asString(err.stdout), maxOutput),
          stderr: truncateOutput(asString(err.stderr), maxOutput),
          durationMs: Date.now() - started,
          timedOut: false,
        };
      }
      const message = err instanceof Error ? err.message : String(err);
      if (/timed? ?out|abort/i.test(message)) {
        return { exitCode: null, stdout: '', stderr: message, durationMs: Date.now() - started, timedOut: true };
      }
      throw err;
    }
  }

  async writeFile(name: string, path: string, data: string | Buffer, mode?: number): Promise<void> {
    const fs = this.client.sprite(name).filesystem();
    await fs.mkdir(dirname(path), { recursive: true });
    await fs.writeFile(path, data, mode !== undefined ? { mode } : undefined);
  }

  async checkpoint(name: string, comment: string): Promise<string> {
    const sprite = this.client.sprite(name);
    const stream = await sprite.createCheckpoint(comment);
    let detectedId: string | undefined;
    await stream.processAll((msg) => {
      if (msg.type === 'error') throw new Error(`checkpoint failed: ${msg.error ?? msg.data ?? 'unknown error'}`);
      const text = `${msg.data ?? ''}`;
      const m = /\b(v\d+)\b/.exec(text) ?? /"id"\s*:\s*"([^"]+)"/.exec(text);
      if (m?.[1]) detectedId = m[1];
    });
    if (detectedId) return detectedId;
    const checkpoints = await sprite.listCheckpoints();
    const match = checkpoints
      .filter((c) => c.comment === comment)
      .sort((a, b) => new Date(b.createTime).getTime() - new Date(a.createTime).getTime())[0];
    if (!match) throw new Error(`checkpoint "${comment}" was created but could not be located`);
    return match.id;
  }

  async restore(name: string, checkpointId: string): Promise<void> {
    const stream = await this.client.sprite(name).restoreCheckpoint(checkpointId);
    await stream.processAll((msg) => {
      if (msg.type === 'error') throw new Error(`restore failed: ${msg.error ?? msg.data ?? 'unknown error'}`);
    });
  }

  async setNetworkPolicy(name: string, allowDomains: string[]): Promise<boolean> {
    try {
      await this.client.sprite(name).updateNetworkPolicy({
        rules: [
          ...allowDomains.map((domain) => ({ domain, action: 'allow' as const })),
          { domain: '*', action: 'deny' as const },
        ],
      });
      return true;
    } catch (err) {
      this.log.warn({ err, name }, 'failed to apply Sprite network policy (continuing with observation-only egress)');
      return false;
    }
  }

  /**
   * Sprites hibernate automatically once no exec sessions or connections are active, so "sleep"
   * means: terminate stray sessions and drop our control connection. Billing scales to zero.
   */
  async sleep(name: string): Promise<void> {
    const sprite = this.client.sprite(name);
    try {
      const sessions = await sprite.listSessions();
      for (const s of sessions) {
        const id = (s as { id?: string | number }).id;
        if (id === undefined) continue;
        const kill = await sprite.killSession(String(id), 'SIGKILL');
        for await (const _evt of kill) {
          /* drain */
        }
      }
    } catch (err) {
      this.log.debug({ err, name }, 'session cleanup before sleep failed');
    }
    if (sprite.hasControlConnection()) sprite.closeControlConnection();
  }

  /** Any request transparently wakes a hibernated Sprite; we issue a no-op exec to force it. */
  async wake(name: string): Promise<void> {
    const res = await this.exec(name, 'true', { timeoutMs: 120_000 });
    if (res.exitCode !== 0) throw new Error(`failed to wake sprite ${name}: ${res.stderr}`);
  }

  async destroy(name: string): Promise<void> {
    try {
      await this.client.deleteSprite(name);
    } catch (err) {
      if (err instanceof APIError && err.statusCode === 404) return;
      throw err;
    }
  }
}

/* -------------------------------------------------------------------------------------------------
 * Local sandbox driver — demo / development only
 * -----------------------------------------------------------------------------------------------*/

export class LocalSandboxDriver implements SpriteDriver {
  readonly kind = 'local-sandbox' as const;
  readonly isolated = false;
  private readonly baseDir: string;

  constructor(
    private readonly log: Logger,
    baseDir: string = join(tmpdir(), 'spriteguard-sprites'),
  ) {
    this.baseDir = resolve(baseDir);
  }

  paths(name: string): SpritePaths {
    const root = join(this.baseDir, name);
    return { root, repo: join(root, 'repo'), tools: join(root, 'tools') };
  }

  private assertInside(name: string, path: string): string {
    const root = this.paths(name).root;
    const abs = resolve(path);
    if (abs !== root && !abs.startsWith(root + sep)) throw new Error(`path escapes local sandbox: ${path}`);
    return abs;
  }

  async create(name: string): Promise<void> {
    const p = this.paths(name);
    await mkdir(p.repo, { recursive: true });
    await mkdir(p.tools, { recursive: true });
    await mkdir(join(p.root, 'home'), { recursive: true });
  }

  async exists(name: string): Promise<boolean> {
    try {
      return (await stat(this.paths(name).root)).isDirectory();
    } catch {
      return false;
    }
  }

  exec(name: string, script: string, opts: SpriteExecOptions = {}): Promise<SpriteExecResult> {
    const p = this.paths(name);
    const maxOutput = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT;
    const started = Date.now();
    return new Promise((resolvePromise, reject) => {
      const child = spawn('/bin/bash', ['-c', script], {
        cwd: opts.cwd ? this.assertInside(name, opts.cwd) : p.root,
        detached: true,
        env: {
          PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
          HOME: join(p.root, 'home'),
          LANG: 'C.UTF-8',
          TMPDIR: join(p.root, 'home'),
          npm_config_cache: join(p.root, 'home', '.npm'),
          ...opts.env,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      child.stdout.setEncoding('utf8').on('data', (c: string) => {
        if (stdout.length < maxOutput * 2) stdout += c;
      });
      child.stderr.setEncoding('utf8').on('data', (c: string) => {
        if (stderr.length < maxOutput * 2) stderr += c;
      });
      const timer = setTimeout(() => {
        timedOut = true;
        try {
          if (child.pid) process.kill(-child.pid, 'SIGKILL');
        } catch {
          child.kill('SIGKILL');
        }
      }, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolvePromise({
          exitCode: timedOut ? null : code,
          stdout: truncateOutput(stdout, maxOutput),
          stderr: truncateOutput(stderr, maxOutput),
          durationMs: Date.now() - started,
          timedOut,
        });
      });
    });
  }

  async writeFile(name: string, path: string, data: string | Buffer, mode?: number): Promise<void> {
    const abs = this.assertInside(name, path);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, data, mode !== undefined ? { mode } : undefined);
  }

  async checkpoint(name: string, comment: string): Promise<string> {
    const p = this.paths(name);
    const dir = join(p.root, '.checkpoints');
    await mkdir(dir, { recursive: true });
    const existing = await readdir(dir);
    const id = `v${existing.length + 1}`;
    await cp(p.repo, join(dir, id, 'repo'), { recursive: true, verbatimSymlinks: true });
    await writeFile(join(dir, id, 'COMMENT'), comment);
    this.log.debug({ name, id, comment }, 'local checkpoint created');
    return id;
  }

  async restore(name: string, checkpointId: string): Promise<void> {
    if (!/^v\d+$/.test(checkpointId)) throw new Error(`invalid checkpoint id ${checkpointId}`);
    const p = this.paths(name);
    const src = join(p.root, '.checkpoints', checkpointId, 'repo');
    await rm(p.repo, { recursive: true, force: true });
    await cp(src, p.repo, { recursive: true, verbatimSymlinks: true });
  }

  async setNetworkPolicy(): Promise<boolean> {
    return false; // Not enforceable on the host — egress is observed, not blocked.
  }

  async sleep(): Promise<void> {
    /* state-only in local mode */
  }

  async wake(name: string): Promise<void> {
    if (!(await this.exists(name))) throw new Error(`local sandbox ${name} no longer exists`);
  }

  async destroy(name: string): Promise<void> {
    await rm(this.paths(name).root, { recursive: true, force: true });
  }
}

/* -------------------------------------------------------------------------------------------------
 * SpriteManager — lifecycle + state tracking on top of a driver
 * -----------------------------------------------------------------------------------------------*/

export type SpriteStateListener = (name: string, state: SpriteState) => void | Promise<void>;

export class SpriteManager {
  private readonly states = new Map<string, SpriteState>();
  private readonly listeners: SpriteStateListener[] = [];

  constructor(
    readonly driver: SpriteDriver,
    private readonly prefix: string,
    private readonly log: Logger,
  ) {}

  onStateChange(listener: SpriteStateListener): void {
    this.listeners.push(listener);
  }

  private async setState(name: string, state: SpriteState): Promise<void> {
    this.states.set(name, state);
    for (const l of this.listeners) {
      try {
        await l(name, state);
      } catch (err) {
        this.log.warn({ err, name, state }, 'sprite state listener failed');
      }
    }
  }

  stateOf(name: string): SpriteState {
    return this.states.get(name) ?? 'none';
  }

  /** Deterministic, DNS-safe Sprite name for a PR revision. */
  nameFor(repoFullName: string, prNumber: number, headSha: string): string {
    const slug = repoFullName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const suffix = `-pr${prNumber}-${headSha.slice(0, 7).toLowerCase()}`;
    const maxSlug = 63 - this.prefix.length - 1 - suffix.length;
    return `${this.prefix}-${slug.slice(0, Math.max(1, maxSlug)).replace(/-+$/, '')}${suffix}`;
  }

  paths(name: string): SpritePaths {
    return this.driver.paths(name);
  }

  async provision(name: string, labels: string[]): Promise<SpritePaths> {
    await this.setState(name, 'creating');
    await this.driver.create(name, labels);
    const p = this.driver.paths(name);
    const res = await this.driver.exec(name, `rm -rf "${p.repo}" && mkdir -p "${p.repo}" "${p.tools}"`, { timeoutMs: 120_000 });
    if (res.exitCode !== 0) throw new Error(`failed to prepare sprite workspace: ${res.stderr}`);
    await this.setState(name, 'running');
    this.log.info({ name, driver: this.driver.kind }, 'sprite provisioned');
    return p;
  }

  async exec(name: string, script: string, opts?: SpriteExecOptions): Promise<SpriteExecResult> {
    if (this.stateOf(name) === 'sleeping') await this.wake(name);
    return this.driver.exec(name, script, opts);
  }

  async writeFile(name: string, path: string, data: string | Buffer, mode?: number): Promise<void> {
    if (this.stateOf(name) === 'sleeping') await this.wake(name);
    await this.driver.writeFile(name, path, data, mode);
  }

  checkpoint(name: string, comment: string): Promise<string> {
    return this.driver.checkpoint(name, comment);
  }

  restore(name: string, checkpointId: string): Promise<void> {
    return this.driver.restore(name, checkpointId);
  }

  setNetworkPolicy(name: string, allow: string[]): Promise<boolean> {
    return this.driver.setNetworkPolicy(name, allow);
  }

  /** Checkpoint the verified state, then let the Sprite scale to zero while awaiting human approval. */
  async hibernate(name: string, comment: string): Promise<string> {
    const id = await this.driver.checkpoint(name, comment);
    await this.driver.sleep(name);
    await this.setState(name, 'sleeping');
    this.log.info({ name, checkpoint: id }, 'sprite checkpointed and sleeping');
    return id;
  }

  async wake(name: string, checkpointId?: string): Promise<void> {
    await this.driver.wake(name);
    if (checkpointId) await this.driver.restore(name, checkpointId);
    await this.setState(name, 'running');
    this.log.info({ name, checkpoint: checkpointId }, 'sprite woken');
  }

  async exists(name: string): Promise<boolean> {
    return this.driver.exists(name);
  }

  async destroy(name: string): Promise<void> {
    try {
      await this.driver.destroy(name);
    } finally {
      await this.setState(name, 'destroyed');
      this.log.info({ name }, 'sprite destroyed');
    }
  }
}

export interface SpriteManagerOptions {
  localSandboxMode: boolean;
  token: string | undefined;
  apiUrl: string;
  prefix: string;
}

export function createSpriteManager(opts: SpriteManagerOptions, log: Logger): SpriteManager {
  if (opts.localSandboxMode) {
    log.warn('LOCAL_SANDBOX_MODE=true — using the local sandbox driver (no hardware isolation).');
    return new SpriteManager(new LocalSandboxDriver(log), opts.prefix, log);
  }
  if (!opts.token) throw new Error('SPRITES_TOKEN is required when LOCAL_SANDBOX_MODE=false');
  return new SpriteManager(new SpritesApiDriver(opts.token, opts.apiUrl, log), opts.prefix, log);
}
