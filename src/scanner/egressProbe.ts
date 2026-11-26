import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import type { Logger } from '../logger.js';
import type { SpriteManager } from '../fly/spriteManager.js';
import type {
  CanaryHit,
  CommandRun,
  EgressDomain,
  EgressEvent,
  EgressReport,
  ProjectType,
  TestOutcome,
} from '../types.js';
import { dedupeLeaks, isEnvFilePath, isScannablePath, scanTextRaw, toPublicLeak, type RawSecretMatch } from './secretScanner.js';

/**
 * Layer B — Runtime & Network Egress Probe.
 *
 * Executes dependency installation, build scripts, and tests inside the
 * isolated Sprite with:
 *  1. Node (`NODE_OPTIONS`) and Python (`PYTHONPATH/sitecustomize.py`) preload
 *     hooks logging every DNS lookup, TCP socket connect, and HTTP(S)/fetch
 *     destination to an NDJSON file.
 *  2. Per-run synthetic canary secrets in environment variables to detect active
 *     credential exfiltration across stdout, stderr, or outbound URLs.
 *  3. Post-run inspection of runtime stdout/stderr and generated build output
 *     for leaked secrets.
 */

export interface CanarySet {
  vars: Record<string, string>;
  values: string[];
}

export function generateCanaries(): CanarySet {
  const tag = randomBytes(6).toString('hex').toUpperCase();
  const aws = `AKIACANARY${tag.slice(0, 10)}`;
  const key = `sg_canary_${randomBytes(10).toString('hex')}`;
  const tok = `sg_tok_${randomBytes(10).toString('hex')}`;
  return {
    vars: {
      AWS_ACCESS_KEY_ID: aws,
      SPRITEGUARD_CANARY_KEY: key,
      SPRITEGUARD_CANARY_TOKEN: tok,
    },
    values: [aws, key, tok],
  };
}

const NODE_EGRESS_HOOK = `'use strict';
if (globalThis[Symbol.for('spriteguard.egressHookInstalled')]) return;
globalThis[Symbol.for('spriteguard.egressHookInstalled')] = true;

const fs = require('node:fs');
const dns = require('node:dns');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');

const LOG_PATH = process.env.SPRITEGUARD_EGRESS_LOG;
const PHASE = process.env.SPRITEGUARD_PHASE || 'runtime';

function record(kind, host, port, url, via) {
  if (!LOG_PATH || !host) return;
  try {
    const cleanHost = String(host).replace(/^\\[|\\]$/g, '').trim().toLowerCase();
    if (!cleanHost) return;
    const entry = { kind, host: cleanHost, phase: PHASE, via };
    if (typeof port === 'number' && Number.isFinite(port) && port > 0) entry.port = port;
    if (url) entry.url = String(url).slice(0, 1024);
    fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + '\\n');
  } catch {}
}

function wrapDns(fnName) {
  const orig = dns[fnName];
  if (typeof orig !== 'function') return;
  dns[fnName] = function wrappedDns(hostname, ...rest) {
    if (typeof hostname === 'string') record('dns', hostname, undefined, undefined, 'dns.' + fnName);
    return orig.call(this, hostname, ...rest);
  };
}
wrapDns('lookup');
wrapDns('resolve');
wrapDns('resolve4');
wrapDns('resolve6');

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function wrappedConnect(...args) {
  try {
    let first = args[0];
    if (Array.isArray(first)) first = first[0];
    if (first && typeof first === 'object') {
      const host = first.host || first.hostname || (first.path ? undefined : 'localhost');
      const port = typeof first.port === 'number' ? first.port : Number(first.port);
      if (host) record('connect', host, Number.isFinite(port) ? port : undefined, undefined, 'net.connect');
    } else if (typeof first === 'number') {
      const host = typeof args[1] === 'string' ? args[1] : 'localhost';
      record('connect', host, first, undefined, 'net.connect');
    }
  } catch {}
  return origConnect.apply(this, args);
};

function extractHttpTarget(input, options, defaultProto) {
  if (typeof input === 'string') {
    try {
      const u = new URL(input);
      return {
        host: u.hostname,
        port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
        url: u.href,
      };
    } catch {}
  } else if (input && typeof input === 'object' && input instanceof URL) {
    return {
      host: input.hostname,
      port: input.port ? Number(input.port) : input.protocol === 'https:' ? 443 : 80,
      url: input.href,
    };
  }
  const opts = (typeof input === 'object' && input && !(input instanceof URL)) ? input : (options && typeof options === 'object' ? options : {});
  const host = opts.hostname || opts.host || (opts.socketPath ? undefined : 'localhost');
  const rawPort = opts.port;
  const port = rawPort ? Number(rawPort) : defaultProto === 'https:' ? 443 : 80;
  const path = opts.path || '/';
  const cleanHost = host ? String(host).split(':')[0] : undefined;
  return {
    host: cleanHost,
    port: Number.isFinite(port) ? port : undefined,
    url: cleanHost ? defaultProto + '//' + cleanHost + path : undefined,
  };
}

function wrapHttp(mod, proto, label) {
  const origReq = mod.request;
  mod.request = function wrappedRequest(input, options, cb) {
    try {
      const target = extractHttpTarget(input, options, proto);
      if (target.host) record('http', target.host, target.port, target.url, label + '.request');
    } catch {}
    return origReq.call(this, input, options, cb);
  };
  const origGet = mod.get;
  mod.get = function wrappedGet(input, options, cb) {
    try {
      const target = extractHttpTarget(input, options, proto);
      if (target.host) record('http', target.host, target.port, target.url, label + '.get');
    } catch {}
    return origGet.call(this, input, options, cb);
  };
}
wrapHttp(http, 'http:', 'http');
wrapHttp(https, 'https:', 'https');

if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function wrappedFetch(resource, init) {
    try {
      const rawUrl = typeof resource === 'string' ? resource : resource instanceof URL ? resource.href : resource && resource.url;
      if (rawUrl) {
        const u = new URL(rawUrl);
        const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
        record('http', u.hostname, port, u.href, 'fetch');
      }
    } catch {}
    return origFetch.call(this, resource, init);
  };
}
`;

const PYTHON_SITECUSTOMIZE = `import json, os, socket, urllib.request

_LOG_PATH = os.environ.get("SPRITEGUARD_EGRESS_LOG")
_PHASE = os.environ.get("SPRITEGUARD_PHASE", "runtime")

def _record(kind, host, port=None, url=None, via="python"):
    if not _LOG_PATH or not host:
        return
    try:
        clean = str(host).strip("[]").strip().lower()
        if not clean:
            return
        entry = {"kind": kind, "host": clean, "phase": _PHASE, "via": via}
        if isinstance(port, int) and port > 0:
            entry["port"] = port
        if url:
            entry["url"] = str(url)[:1024]
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\\n")
    except Exception:
        pass

_orig_getaddrinfo = socket.getaddrinfo
def _sg_getaddrinfo(host, port, *args, **kwargs):
    if host:
        p = port if isinstance(port, int) else None
        _record("dns", host, p, None, "socket.getaddrinfo")
    return _orig_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _sg_getaddrinfo

_orig_create_conn = socket.create_connection
def _sg_create_connection(address, *args, **kwargs):
    try:
        if isinstance(address, tuple) and len(address) >= 2:
            _record("connect", address[0], int(address[1]), None, "socket.create_connection")
    except Exception:
        pass
    return _orig_create_conn(address, *args, **kwargs)
socket.create_connection = _sg_create_connection

_orig_urlopen = urllib.request.urlopen
def _sg_urlopen(url, *args, **kwargs):
    try:
        from urllib.parse import urlparse
        raw = url.full_url if hasattr(url, "full_url") else str(url)
        u = urlparse(raw)
        if u.hostname:
            port = u.port or (443 if u.scheme == "https" else 80)
            _record("http", u.hostname, port, raw, "urllib.urlopen")
    except Exception:
        pass
    return _orig_urlopen(url, *args, **kwargs)
urllib.request.urlopen = _sg_urlopen
`;

const KNOWN_EXFIL_HOST_PATTERN =
  /(?:webhook\.site|requestbin|pipedream|ngrok|oastify|interact\.sh|burpcollaborator|pastebin\.com|transfer\.sh|0x0\.st|exfil|attacker|c2-server)/i;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

function isLoopbackOrLocal(host: string): boolean {
  const h = host.toLowerCase();
  return LOOPBACK_HOSTS.has(h) || h.endsWith('.local') || h.endsWith('.localhost');
}

export function isAllowlistedHost(host: string, allowlist: string[]): boolean {
  const h = host.toLowerCase().replace(/\.+$/, '');
  if (isLoopbackOrLocal(h)) return true;
  for (const rawRule of allowlist) {
    const rule = rawRule.toLowerCase().trim();
    if (!rule) continue;
    if (rule.startsWith('*.')) {
      const suffix = rule.slice(1); // .npmjs.org
      if (h.endsWith(suffix) || h === rule.slice(2)) return true;
    } else if (h === rule || h.endsWith(`.${rule}`)) {
      return true;
    }
  }
  return false;
}

function extractUrlsFromText(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'`<>()[\]]{4,}/gi) ?? [];
  return matches.map((u) => u.replace(/[.,;:!?]+$/, ''));
}

export function aggregateEgressEvents(
  events: EgressEvent[],
  allowlist: string[],
  canaries: CanarySet,
  extraUrls: Array<{ url: string; phase: string }> = [],
): { domains: EgressDomain[]; rawIps: string[]; canaryHits: CanaryHit[] } {
  const allEvents = [...events];
  for (const extra of extraUrls) {
    try {
      const u = new URL(extra.url);
      allEvents.push({
        kind: 'http',
        host: u.hostname.toLowerCase(),
        port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
        url: u.href,
        phase: extra.phase,
        via: 'output-url',
      });
    } catch {
      /* ignore malformed URLs */
    }
  }

  const byHost = new Map<
    string,
    {
      ports: Set<number>;
      phases: Set<string>;
      hits: number;
      urls: Set<string>;
    }
  >();
  const rawIps = new Set<string>();
  const canaryHits: CanaryHit[] = [];

  for (const ev of allEvents) {
    const host = ev.host.trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) continue;

    if (ev.url) {
      for (const canaryVal of canaries.values) {
        if (ev.url.includes(canaryVal)) {
          canaryHits.push({
            canary: `${canaryVal.slice(0, 8)}…`,
            channel: 'egress_url',
            detail: `Canary secret observed in outbound request URL (${ev.url.split(canaryVal).join('[CANARY]')})`,
          });
        }
      }
    }

    if (isLoopbackOrLocal(host)) continue;

    if (isIP(host) !== 0) {
      rawIps.add(host);
    }

    let bucket = byHost.get(host);
    if (!bucket) {
      bucket = { ports: new Set(), phases: new Set(), hits: 0, urls: new Set() };
      byHost.set(host, bucket);
    }
    bucket.hits += 1;
    bucket.phases.add(ev.phase);
    if (ev.port && Number.isFinite(ev.port)) bucket.ports.add(ev.port);
    if (ev.url && bucket.urls.size < 5) {
      let safeUrl = ev.url;
      for (const c of canaries.values) safeUrl = safeUrl.split(c).join('[CANARY]');
      bucket.urls.add(safeUrl);
    }
  }

  const domains: EgressDomain[] = [];
  for (const [host, data] of byHost) {
    const isIp = isIP(host) !== 0;
    const allowlisted = !isIp && isAllowlistedHost(host, allowlist);
    const reasons: string[] = [];

    if (isIp) reasons.push('Direct raw IP connection (bypasses DNS allowlist)');
    if (KNOWN_EXFIL_HOST_PATTERN.test(host)) reasons.push('Matches known webhook/exfiltration domain pattern');
    if (!allowlisted && !isIp) reasons.push('Host not in Sprite egress allowlist');
    for (const url of data.urls) {
      if (url.includes('[CANARY]')) {
        reasons.push('Canary credential exfiltrated in outbound URL');
        break;
      }
    }

    const flagged = reasons.length > 0;
    domains.push({
      host,
      ports: [...data.ports].sort((a, b) => a - b),
      phases: [...data.phases].sort(),
      hits: data.hits,
      allowlisted,
      flagged,
      reasons,
      sampleUrls: [...data.urls],
    });
  }

  domains.sort((a, b) => Number(b.flagged) - Number(a.flagged) || b.hits - a.hits || a.host.localeCompare(b.host));

  return {
    domains,
    rawIps: [...rawIps].sort(),
    canaryHits,
  };
}

/* -------------------------------------------------------------------------------------------------
 * Workspace Inspection inside Sprite (env files, build outputs, project detection)
 * -----------------------------------------------------------------------------------------------*/

interface RemoteFileEntry {
  path: string;
  content: string;
}

async function readSpriteFilesJson(sprites: SpriteManager, spriteName: string, script: string): Promise<RemoteFileEntry[]> {
  const res = await sprites.exec(spriteName, script, {
    cwd: sprites.paths(spriteName).repo,
    timeoutMs: 60_000,
  });
  const markerStart = '__SG_FILES_BEGIN__';
  const markerEnd = '__SG_FILES_END__';
  const s = res.stdout.indexOf(markerStart);
  const e = res.stdout.indexOf(markerEnd);
  if (s === -1 || e === -1 || e <= s) return [];
  try {
    const parsed = JSON.parse(res.stdout.slice(s + markerStart.length, e).trim()) as { files?: RemoteFileEntry[] };
    return Array.isArray(parsed.files) ? parsed.files : [];
  } catch {
    return [];
  }
}

export async function scanWorkspaceFiles(
  sprites: SpriteManager,
  spriteName: string,
  kinds: Array<'env' | 'build' | 'all'>,
): Promise<RawSecretMatch[]> {
  const modeArg = kinds.join(',');
  const repoPath = sprites.paths(spriteName).repo;
  const nodeReader = `node -e '
const fs = require("fs");
const path = require("path");
const root = process.cwd();
const modes = new Set(process.argv[1].split(","));
const ignore = new Set([".git", "node_modules", ".sg-venv", ".venv", "__pycache__", ".checkpoints"]);
const buildDirs = new Set(["dist", "build", ".next", "out"]);
const out = [];
function walk(dir, inBuild) {
  if (out.length >= 60) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const ent of entries) {
    if (out.length >= 60) break;
    if (ignore.has(ent.name)) continue;
    const full = path.join(dir, ent.name);
    const rel = path.relative(root, full).split(path.sep).join("/");
    if (ent.isDirectory()) {
      walk(full, inBuild || buildDirs.has(ent.name));
    } else if (ent.isFile()) {
      const isEnv = /^\\.env(\\..*)?$/i.test(ent.name) && !/\\.(example|sample|template|dist|defaults)$/i.test(ent.name);
      const want = modes.has("all") || (modes.has("env") && isEnv) || (modes.has("build") && inBuild);
      if (!want) continue;
      try {
        const st = fs.statSync(full);
        if (st.size > 262144) continue;
        const buf = fs.readFileSync(full);
        if (buf.includes(0)) continue;
        out.push({ path: rel, content: buf.toString("utf8") });
      } catch {}
    }
  }
}
walk(root, false);
process.stdout.write("__SG_FILES_BEGIN__\\n" + JSON.stringify({ files: out }) + "\\n__SG_FILES_END__\\n");
' "${modeArg}"`;

  const files = await readSpriteFilesJson(sprites, spriteName, `cd "${repoPath}" && ${nodeReader}`);
  const matches: RawSecretMatch[] = [];
  for (const f of files) {
    if (!isScannablePath(f.path)) continue;
    const isEnv = isEnvFilePath(f.path);
    const source = isEnv ? 'env_file' : kinds.includes('all') ? 'patched_tree' : 'build_output';
    matches.push(
      ...scanTextRaw(f.content, {
        file: f.path,
        source,
        entropy: isEnv || kinds.includes('all'),
      }),
    );
  }
  return dedupeLeaks(matches);
}

interface PackageMeta {
  hasPackageJson: boolean;
  hasLockfile: boolean;
  hasDeps: boolean;
  hasBuild: boolean;
  hasTest: boolean;
  testCmd?: string;
}

async function inspectNodeProject(sprites: SpriteManager, spriteName: string): Promise<PackageMeta> {
  const repo = sprites.paths(spriteName).repo;
  const cmd = `cd "${repo}" && node -e '
const fs = require("fs");
if (!fs.existsSync("package.json")) { console.log(JSON.stringify({ hasPackageJson: false })); process.exit(0); }
const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
const deps = Object.keys(pkg.dependencies || {}).length + Object.keys(pkg.devDependencies || {}).length + Object.keys(pkg.optionalDependencies || {}).length;
const scripts = pkg.scripts || {};
const testStr = typeof scripts.test === "string" ? scripts.test : "";
const isStub = !testStr || /no test specified/i.test(testStr);
console.log(JSON.stringify({
  hasPackageJson: true,
  hasLockfile: fs.existsSync("package-lock.json"),
  hasDeps: deps > 0,
  hasBuild: typeof scripts.build === "string" && scripts.build.trim().length > 0,
  hasTest: !isStub,
  testCmd: isStub ? undefined : testStr,
}));
'`;
  const res = await sprites.exec(spriteName, cmd, { cwd: repo, timeoutMs: 30_000 });
  if (res.exitCode !== 0) return { hasPackageJson: false, hasLockfile: false, hasDeps: false, hasBuild: false, hasTest: false };
  try {
    return JSON.parse(res.stdout.trim().split('\n').pop() ?? '{}') as PackageMeta;
  } catch {
    return { hasPackageJson: false, hasLockfile: false, hasDeps: false, hasBuild: false, hasTest: false };
  }
}

async function inspectPythonProject(
  sprites: SpriteManager,
  spriteName: string,
): Promise<{ hasPython: boolean; hasRequirements: boolean; hasPyproject: boolean; hasTests: boolean }> {
  const repo = sprites.paths(spriteName).repo;
  const res = await sprites.exec(
    spriteName,
    `cd "${repo}" && python3 -c '
import json, os, glob
has_req = os.path.exists("requirements.txt")
has_pyp = os.path.exists("pyproject.toml")
has_setup = os.path.exists("setup.py")
tests = glob.glob("test_*.py") + glob.glob("tests/**/*.py", recursive=True)
print(json.dumps({
  "hasPython": has_req or has_pyp or has_setup or len(glob.glob("*.py")) > 0,
  "hasRequirements": has_req,
  "hasPyproject": has_pyp,
  "hasTests": len(tests) > 0,
}))
'`,
    { cwd: repo, timeoutMs: 30_000 },
  );
  if (res.exitCode !== 0) return { hasPython: false, hasRequirements: false, hasPyproject: false, hasTests: false };
  try {
    return JSON.parse(res.stdout.trim().split('\n').pop() ?? '{}') as {
      hasPython: boolean;
      hasRequirements: boolean;
      hasPyproject: boolean;
      hasTests: boolean;
    };
  } catch {
    return { hasPython: false, hasRequirements: false, hasPyproject: false, hasTests: false };
  }
}

export async function detectProjectType(sprites: SpriteManager, spriteName: string): Promise<ProjectType> {
  const nodeMeta = await inspectNodeProject(sprites, spriteName);
  if (nodeMeta.hasPackageJson) return 'node';
  const pyMeta = await inspectPythonProject(sprites, spriteName);
  if (pyMeta.hasPython) return 'python';
  return 'unknown';
}

async function installHooksInSprite(sprites: SpriteManager, spriteName: string): Promise<{
  nodeHookPath: string;
  pyHookDir: string;
  egressLogPath: string;
}> {
  const tools = sprites.paths(spriteName).tools;
  const nodeHookPath = `${tools}/egress-hook.cjs`;
  const pyHookDir = `${tools}/pyhook`;
  const egressLogPath = `${tools}/egress.ndjson`;
  await sprites.writeFile(spriteName, nodeHookPath, NODE_EGRESS_HOOK, 0o644);
  await sprites.writeFile(spriteName, `${pyHookDir}/sitecustomize.py`, PYTHON_SITECUSTOMIZE, 0o644);
  await sprites.writeFile(spriteName, egressLogPath, '', 0o644);
  return { nodeHookPath, pyHookDir, egressLogPath };
}

async function readEgressEvents(sprites: SpriteManager, spriteName: string, logPath: string): Promise<EgressEvent[]> {
  const res = await sprites.exec(spriteName, `cat "${logPath}" 2>/dev/null || true`, { timeoutMs: 30_000 });
  const events: EgressEvent[] = [];
  for (const line of res.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as EgressEvent;
      if (parsed && typeof parsed.host === 'string') events.push(parsed);
    } catch {
      /* ignore partial line */
    }
  }
  return events;
}

function scanOutputForLeaksAndCanaries(
  commands: CommandRun[],
  canaries: CanarySet,
): { runtimeLeaks: RawSecretMatch[]; canaryHits: CanaryHit[]; extraUrls: Array<{ url: string; phase: string }> } {
  const runtimeLeaks: RawSecretMatch[] = [];
  const canaryHits: CanaryHit[] = [];
  const extraUrls: Array<{ url: string; phase: string }> = [];
  const canaryValues = new Set(canaries.values);

  for (const cmd of commands) {
    for (const [channel, text] of [
      ['stdout', cmd.stdoutTail],
      ['stderr', cmd.stderrTail],
    ] as const) {
      if (!text) continue;
      for (const val of canaryValues) {
        if (text.includes(val)) {
          canaryHits.push({
            canary: `${val.slice(0, 8)}…`,
            channel,
            detail: `Canary environment variable leaked to ${channel} during "${cmd.label}"`,
          });
        }
      }
      for (const u of extractUrlsFromText(text)) {
        extraUrls.push({ url: u, phase: cmd.label });
      }
      const leaks = scanTextRaw(text, {
        file: `<${cmd.label}:${channel}>`,
        source: 'runtime_output',
        entropy: false,
      }).filter((l) => !canaryValues.has(l.raw));
      runtimeLeaks.push(...leaks);
    }
  }

  return { runtimeLeaks: dedupeLeaks(runtimeLeaks), canaryHits, extraUrls };
}

function tail(text: string, maxChars = 6000): string {
  if (text.length <= maxChars) return text;
  return `…[truncated]…\n${text.slice(-maxChars)}`;
}

/* -------------------------------------------------------------------------------------------------
 * Public Probe & Test Runner
 * -----------------------------------------------------------------------------------------------*/

export interface EgressProbeOptions {
  sprites: SpriteManager;
  spriteName: string;
  allowlist: string[];
  installTimeoutSec: number;
  testTimeoutSec: number;
  allowLocalExec: boolean;
  log: Logger;
}

export async function runEgressProbe(
  opts: EgressProbeOptions,
): Promise<EgressReport & { rawRuntimeLeaks: RawSecretMatch[]; testsBefore: TestOutcome }> {
  const { sprites, spriteName, allowlist, log } = opts;

  if (!sprites.driver.isolated && !opts.allowLocalExec) {
    return {
      projectType: await detectProjectType(sprites, spriteName),
      commands: [],
      domains: [],
      rawIps: [],
      runtimeLeaks: [],
      rawRuntimeLeaks: [],
      canaryExfiltrations: [],
      skipped:
        'Runtime execution skipped in LOCAL_SANDBOX_MODE (set LOCAL_ALLOW_UNTRUSTED_EXEC=true or trigger a local demo fixture to execute).',
      testsBefore: { ran: false, passed: true, exitCode: null, summary: 'Skipped in unisolated local sandbox' },
    };
  }

  const hooks = await installHooksInSprite(sprites, spriteName);
  const canaries = generateCanaries();
  const repoDir = sprites.paths(spriteName).repo;
  const commands: CommandRun[] = [];
  let testsBefore: TestOutcome = { ran: false, passed: true, exitCode: null, summary: 'No test suite detected' };

  const nodeMeta = await inspectNodeProject(sprites, spriteName);
  let projectType: ProjectType = 'unknown';

  const makeEnv = (phase: string): Record<string, string> => ({
    ...canaries.vars,
    SPRITEGUARD_EGRESS_LOG: hooks.egressLogPath,
    SPRITEGUARD_PHASE: phase,
    NODE_OPTIONS: `--require=${hooks.nodeHookPath}`,
    PYTHONPATH: hooks.pyHookDir,
    CI: 'true',
  });

  if (nodeMeta.hasPackageJson) {
    projectType = 'node';

    if (nodeMeta.hasDeps) {
      const installCmd = nodeMeta.hasLockfile ? 'npm ci --no-audit --no-fund' : 'npm install --no-audit --no-fund';
      const res = await sprites.exec(spriteName, installCmd, {
        cwd: repoDir,
        env: makeEnv('install'),
        timeoutMs: opts.installTimeoutSec * 1000,
      });
      commands.push({
        label: 'install',
        command: installCmd,
        exitCode: res.exitCode,
        durationMs: res.durationMs,
        timedOut: res.timedOut,
        stdoutTail: tail(res.stdout),
        stderrTail: tail(res.stderr),
      });
    } else {
      commands.push({
        label: 'install',
        command: 'npm install (skipped: 0 declared dependencies)',
        exitCode: 0,
        durationMs: 0,
        timedOut: false,
        stdoutTail: 'No dependencies declared in package.json; install skipped.',
        stderrTail: '',
      });
    }

    if (nodeMeta.hasBuild) {
      const buildCmd = 'npm run build';
      const res = await sprites.exec(spriteName, buildCmd, {
        cwd: repoDir,
        env: makeEnv('build'),
        timeoutMs: opts.testTimeoutSec * 1000,
      });
      commands.push({
        label: 'build',
        command: buildCmd,
        exitCode: res.exitCode,
        durationMs: res.durationMs,
        timedOut: res.timedOut,
        stdoutTail: tail(res.stdout),
        stderrTail: tail(res.stderr),
      });
    }

    if (nodeMeta.hasTest) {
      const testCmd = 'npm test';
      const res = await sprites.exec(spriteName, testCmd, {
        cwd: repoDir,
        env: makeEnv('test'),
        timeoutMs: opts.testTimeoutSec * 1000,
      });
      commands.push({
        label: 'test',
        command: testCmd,
        exitCode: res.exitCode,
        durationMs: res.durationMs,
        timedOut: res.timedOut,
        stdoutTail: tail(res.stdout),
        stderrTail: tail(res.stderr),
      });
      testsBefore = {
        ran: true,
        passed: !res.timedOut && res.exitCode === 0,
        exitCode: res.exitCode,
        command: testCmd,
        summary: res.timedOut
          ? `Tests timed out after ${opts.testTimeoutSec}s`
          : res.exitCode === 0
            ? `Tests passed (${res.durationMs}ms)`
            : `Tests exited with code ${res.exitCode}`,
      };
    }
  } else {
    const pyMeta = await inspectPythonProject(sprites, spriteName);
    if (pyMeta.hasPython) {
      projectType = 'python';
      if (pyMeta.hasRequirements) {
        const installCmd = 'python3 -m venv .sg-venv && .sg-venv/bin/pip install --no-input -r requirements.txt';
        const res = await sprites.exec(spriteName, installCmd, {
          cwd: repoDir,
          env: makeEnv('install'),
          timeoutMs: opts.installTimeoutSec * 1000,
        });
        commands.push({
          label: 'install',
          command: installCmd,
          exitCode: res.exitCode,
          durationMs: res.durationMs,
          timedOut: res.timedOut,
          stdoutTail: tail(res.stdout),
          stderrTail: tail(res.stderr),
        });
      }

      if (pyMeta.hasTests) {
        const pyTestCmd =
          'if [ -x .sg-venv/bin/pytest ]; then .sg-venv/bin/pytest -q; ' +
          'elif command -v pytest >/dev/null 2>&1; then pytest -q; ' +
          'else python3 -m unittest discover; fi';
        const res = await sprites.exec(spriteName, pyTestCmd, {
          cwd: repoDir,
          env: makeEnv('test'),
          timeoutMs: opts.testTimeoutSec * 1000,
        });
        commands.push({
          label: 'test',
          command: 'pytest / python3 -m unittest',
          exitCode: res.exitCode,
          durationMs: res.durationMs,
          timedOut: res.timedOut,
          stdoutTail: tail(res.stdout),
          stderrTail: tail(res.stderr),
        });
        testsBefore = {
          ran: true,
          passed: !res.timedOut && res.exitCode === 0,
          exitCode: res.exitCode,
          command: 'pytest / unittest',
          summary: res.timedOut
            ? `Python tests timed out after ${opts.testTimeoutSec}s`
            : res.exitCode === 0
              ? `Python tests passed (${res.durationMs}ms)`
              : `Python tests exited with code ${res.exitCode}`,
        };
      }
    }
  }

  const events = await readEgressEvents(sprites, spriteName, hooks.egressLogPath);
  const { runtimeLeaks: rawRuntimeLeaks, canaryHits: outCanaries, extraUrls } = scanOutputForLeaksAndCanaries(
    commands,
    canaries,
  );
  const agg = aggregateEgressEvents(events, allowlist, canaries, extraUrls);
  const allCanaries = [...outCanaries, ...agg.canaryHits];

  log.info(
    {
      spriteName,
      projectType,
      domains: agg.domains.length,
      flagged: agg.domains.filter((d) => d.flagged).length,
      runtimeLeaks: rawRuntimeLeaks.length,
      canaryHits: allCanaries.length,
    },
    'layer B runtime & egress probe finished',
  );

  return {
    projectType,
    commands,
    domains: agg.domains,
    rawIps: agg.rawIps,
    runtimeLeaks: rawRuntimeLeaks.map(toPublicLeak),
    rawRuntimeLeaks,
    canaryExfiltrations: allCanaries,
    testsBefore,
  };
}

export interface TestRunOptions {
  sprites: SpriteManager;
  spriteName: string;
  allowlist: string[];
  timeoutSec: number;
  allowLocalExec: boolean;
}

export async function runTestSuite(opts: TestRunOptions): Promise<{
  outcome: TestOutcome;
  flaggedEgress: string[];
  runtimeLeaks: RawSecretMatch[];
  canaryHits: CanaryHit[];
  outputTail: string;
}> {
  const { sprites, spriteName, allowlist } = opts;
  if (!sprites.driver.isolated && !opts.allowLocalExec) {
    return {
      outcome: { ran: false, passed: true, exitCode: null, summary: 'Tests skipped in unisolated local mode' },
      flaggedEgress: [],
      runtimeLeaks: [],
      canaryHits: [],
      outputTail: '',
    };
  }

  const hooks = await installHooksInSprite(sprites, spriteName);
  const canaries = generateCanaries();
  const repoDir = sprites.paths(spriteName).repo;
  const env: Record<string, string> = {
    ...canaries.vars,
    SPRITEGUARD_EGRESS_LOG: hooks.egressLogPath,
    SPRITEGUARD_PHASE: 'verify',
    NODE_OPTIONS: `--require=${hooks.nodeHookPath}`,
    PYTHONPATH: hooks.pyHookDir,
    CI: 'true',
  };

  const nodeMeta = await inspectNodeProject(sprites, spriteName);
  let cmdRun: CommandRun | null = null;
  let outcome: TestOutcome = { ran: false, passed: true, exitCode: null, summary: 'No test suite configured' };

  if (nodeMeta.hasPackageJson && nodeMeta.hasTest) {
    const res = await sprites.exec(spriteName, 'npm test', {
      cwd: repoDir,
      env,
      timeoutMs: opts.timeoutSec * 1000,
    });
    cmdRun = {
      label: 'verify',
      command: 'npm test',
      exitCode: res.exitCode,
      durationMs: res.durationMs,
      timedOut: res.timedOut,
      stdoutTail: tail(res.stdout),
      stderrTail: tail(res.stderr),
    };
    outcome = {
      ran: true,
      passed: !res.timedOut && res.exitCode === 0,
      exitCode: res.exitCode,
      command: 'npm test',
      summary: res.timedOut
        ? `Tests timed out after ${opts.timeoutSec}s`
        : res.exitCode === 0
          ? `Tests passed (${res.durationMs}ms)`
          : `Tests failed with exit code ${res.exitCode}`,
    };
  } else {
    const pyMeta = await inspectPythonProject(sprites, spriteName);
    if (pyMeta.hasPython && pyMeta.hasTests) {
      const pyTestCmd =
        'if [ -x .sg-venv/bin/pytest ]; then .sg-venv/bin/pytest -q; ' +
        'elif command -v pytest >/dev/null 2>&1; then pytest -q; ' +
        'else python3 -m unittest discover; fi';
      const res = await sprites.exec(spriteName, pyTestCmd, {
        cwd: repoDir,
        env,
        timeoutMs: opts.timeoutSec * 1000,
      });
      cmdRun = {
        label: 'verify',
        command: 'pytest / unittest',
        exitCode: res.exitCode,
        durationMs: res.durationMs,
        timedOut: res.timedOut,
        stdoutTail: tail(res.stdout),
        stderrTail: tail(res.stderr),
      };
      outcome = {
        ran: true,
        passed: !res.timedOut && res.exitCode === 0,
        exitCode: res.exitCode,
        command: 'pytest / unittest',
        summary: res.timedOut
          ? `Python tests timed out after ${opts.timeoutSec}s`
          : res.exitCode === 0
            ? `Python tests passed (${res.durationMs}ms)`
            : `Python tests failed with exit code ${res.exitCode}`,
      };
    }
  }

  const events = await readEgressEvents(sprites, spriteName, hooks.egressLogPath);
  const { runtimeLeaks, canaryHits: outCanaries, extraUrls } = cmdRun
    ? scanOutputForLeaksAndCanaries([cmdRun], canaries)
    : { runtimeLeaks: [], canaryHits: [], extraUrls: [] };
  const agg = aggregateEgressEvents(events, allowlist, canaries, extraUrls);
  const outputTail = cmdRun ? [cmdRun.stdoutTail, cmdRun.stderrTail].filter(Boolean).join('\n') : '';

  return {
    outcome,
    flaggedEgress: agg.domains.filter((d) => d.flagged).map((d) => d.host),
    runtimeLeaks,
    canaryHits: [...outCanaries, ...agg.canaryHits],
    outputTail,
  };
}
