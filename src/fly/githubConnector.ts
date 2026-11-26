import { createHash } from 'node:crypto';
import { createAppAuth } from '@octokit/auth-app';
import { Octokit } from '@octokit/rest';
import { createTwoFilesPatch } from 'diff';
import type { AppConfig } from '../config.js';
import type { Logger } from '../logger.js';
import type { CommitPatch, PatchFile, PrContext } from '../types.js';

/**
 * Split GitHub connectors.
 *
 * SpriteGuard never hands a single all-powerful credential to any component:
 *
 *  • {@link ReadOnlyGitHubConnector} — used by the orchestrator and audit pipeline. Backed by a
 *    GitHub App installation token *down-scoped* to `contents:read, pull_requests:read, metadata:read`
 *    (or a read-only fine-grained PAT). It materialises source for the Sprite as an unauthenticated
 *    clone URL (public repos) or a tarball streamed in by the trusted orchestrator (private repos), so
 *    no GitHub token ever enters a Sprite.
 *  • {@link GitHubWriteConnector} — held exclusively by the Trusted Publisher. Scoped to
 *    `contents:write, pull_requests:write, issues:write`, it posts reports and commits verified patches.
 */

export type RepoPermission = 'admin' | 'maintain' | 'write' | 'triage' | 'read' | 'none';

export type SourceDelivery =
  | { kind: 'git'; cloneUrl: string; sha: string }
  | { kind: 'tarball'; data: Buffer; sha: string }
  | { kind: 'files'; files: Record<string, string>; sha: string };

export interface ReadOnlyGitHubConnector {
  readonly mode: 'github-app' | 'token' | 'local';
  rememberInstallation(repoFullName: string, installationId: number): void;
  getPullRequest(repoFullName: string, prNumber: number): Promise<PrContext>;
  getPullRequestDiff(repoFullName: string, prNumber: number): Promise<string>;
  listCommitPatches(repoFullName: string, prNumber: number, maxCommits?: number): Promise<CommitPatch[]>;
  getFileContent(repoFullName: string, path: string, ref: string): Promise<string | null>;
  getRepoPermission(repoFullName: string, username: string): Promise<RepoPermission>;
  getSourceDelivery(pr: PrContext): Promise<SourceDelivery>;
}

export interface CommitFilesRequest {
  repoFullName: string;
  branch: string;
  expectedHeadSha: string;
  message: string;
  files: PatchFile[];
}

export interface GitHubWriteConnector {
  readonly mode: 'github-app' | 'token' | 'local';
  rememberInstallation(repoFullName: string, installationId: number): void;
  postComment(repoFullName: string, issueNumber: number, body: string): Promise<number>;
  updateComment(repoFullName: string, commentId: number, body: string): Promise<void>;
  addReaction(repoFullName: string, commentId: number, reaction: '+1' | 'eyes' | 'rocket' | 'confused'): Promise<void>;
  commitFiles(req: CommitFilesRequest): Promise<string>;
}

export class StaleHeadError extends Error {
  constructor(
    readonly expected: string,
    readonly actual: string,
  ) {
    super(`PR head moved from ${expected.slice(0, 7)} to ${actual.slice(0, 7)} since the audit`);
    this.name = 'StaleHeadError';
  }
}

export function splitRepo(repoFullName: string): { owner: string; repo: string } {
  const [owner, repo] = repoFullName.split('/');
  if (!owner || !repo) throw new Error(`invalid repository name: ${repoFullName}`);
  return { owner, repo };
}

export const READ_SCOPE = { contents: 'read', pull_requests: 'read', metadata: 'read' } as const;
export const WRITE_SCOPE = { contents: 'write', pull_requests: 'write', issues: 'write', metadata: 'read' } as const;

type Scope = typeof READ_SCOPE | typeof WRITE_SCOPE;

/* -------------------------------------------------------------------------------------------------
 * Credential broker — issues down-scoped installation tokens (GitHub App) or fixed PATs.
 * -----------------------------------------------------------------------------------------------*/

interface CachedToken {
  token: string;
  expiresAt: number;
}

export class GitHubCredentialBroker {
  private readonly installations = new Map<string, number>();
  private readonly tokens = new Map<string, CachedToken>();
  private readonly appAuth: ReturnType<typeof createAppAuth> | null;
  readonly mode: 'github-app' | 'token';

  constructor(
    private readonly cfg: AppConfig['github'],
    private readonly log: Logger,
  ) {
    if (cfg.appId && cfg.appPrivateKey) {
      this.appAuth = createAppAuth({ appId: cfg.appId, privateKey: cfg.appPrivateKey });
      this.mode = 'github-app';
    } else {
      this.appAuth = null;
      this.mode = 'token';
    }
  }

  rememberInstallation(repoFullName: string, installationId: number): void {
    this.installations.set(repoFullName.toLowerCase(), installationId);
  }

  private async installationFor(repoFullName: string): Promise<number> {
    const key = repoFullName.toLowerCase();
    const known = this.installations.get(key);
    if (known) return known;
    if (!this.appAuth) throw new Error('GitHub App credentials not configured');
    const { token } = await this.appAuth({ type: 'app' });
    const { owner, repo } = splitRepo(repoFullName);
    const appClient = new Octokit({ auth: token, baseUrl: this.cfg.apiUrl });
    const { data } = await appClient.apps.getRepoInstallation({ owner, repo });
    this.installations.set(key, data.id);
    return data.id;
  }

  async octokit(repoFullName: string, scope: Scope): Promise<Octokit> {
    const scopeName = scope === READ_SCOPE ? 'read' : 'write';
    if (!this.appAuth) {
      const token = scopeName === 'read' ? this.cfg.readToken : this.cfg.writeToken;
      if (!token) throw new Error(`GITHUB_${scopeName.toUpperCase()}_TOKEN is not configured`);
      return new Octokit({ auth: token, baseUrl: this.cfg.apiUrl, userAgent: 'spriteguard' });
    }
    const installationId = await this.installationFor(repoFullName);
    const cacheKey = `${installationId}:${scopeName}`;
    const cached = this.tokens.get(cacheKey);
    if (cached && cached.expiresAt - Date.now() > 5 * 60_000) {
      return new Octokit({ auth: cached.token, baseUrl: this.cfg.apiUrl, userAgent: 'spriteguard' });
    }
    const auth = await this.appAuth({ type: 'installation', installationId, permissions: { ...scope } });
    this.tokens.set(cacheKey, { token: auth.token, expiresAt: new Date(auth.expiresAt).getTime() });
    this.log.debug({ installationId, scope: scopeName }, 'issued down-scoped installation token');
    return new Octokit({ auth: auth.token, baseUrl: this.cfg.apiUrl, userAgent: 'spriteguard' });
  }
}

function httpStatus(err: unknown): number | undefined {
  return typeof err === 'object' && err !== null && 'status' in err ? Number((err as { status: unknown }).status) : undefined;
}

/* -------------------------------------------------------------------------------------------------
 * Octokit-backed connectors
 * -----------------------------------------------------------------------------------------------*/

export class OctokitReadOnlyConnector implements ReadOnlyGitHubConnector {
  constructor(
    private readonly broker: GitHubCredentialBroker,
    private readonly log: Logger,
  ) {}

  get mode(): 'github-app' | 'token' {
    return this.broker.mode;
  }

  rememberInstallation(repoFullName: string, installationId: number): void {
    this.broker.rememberInstallation(repoFullName, installationId);
  }

  private client(repoFullName: string): Promise<Octokit> {
    return this.broker.octokit(repoFullName, READ_SCOPE);
  }

  async getPullRequest(repoFullName: string, prNumber: number): Promise<PrContext> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
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
  }

  async getPullRequestDiff(repoFullName: string, prNumber: number): Promise<string> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
    try {
      const res = await gh.pulls.get({ owner, repo, pull_number: prNumber, mediaType: { format: 'diff' } });
      return res.data as unknown as string;
    } catch (err) {
      // Very large PRs cannot be rendered as a single diff — rebuild from per-file patches.
      if (httpStatus(err) !== 406 && httpStatus(err) !== 422) throw err;
      this.log.warn({ repoFullName, prNumber }, 'PR diff too large; rebuilding from file patches');
      const files = await gh.paginate(gh.pulls.listFiles, { owner, repo, pull_number: prNumber, per_page: 100 });
      return files
        .filter((f) => f.patch)
        .map((f) => `diff --git a/${f.filename} b/${f.filename}\n--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch}`)
        .join('\n');
    }
  }

  async listCommitPatches(repoFullName: string, prNumber: number, maxCommits = 50): Promise<CommitPatch[]> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
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
  }

  async getFileContent(repoFullName: string, path: string, ref: string): Promise<string | null> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
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
  }

  async getRepoPermission(repoFullName: string, username: string): Promise<RepoPermission> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
    try {
      const { data } = await gh.repos.getCollaboratorPermissionLevel({ owner, repo, username });
      const role = (data.role_name || data.permission || 'none').toLowerCase();
      if (['admin', 'maintain', 'write', 'triage', 'read'].includes(role)) return role as RepoPermission;
      return data.permission === 'admin' ? 'admin' : data.permission === 'write' ? 'write' : 'read';
    } catch (err) {
      if (httpStatus(err) === 404) return 'none';
      throw err;
    }
  }

  async getSourceDelivery(pr: PrContext): Promise<SourceDelivery> {
    if (!pr.isPrivate) {
      // Public source: the Sprite clones anonymously — no credential is ever needed inside it.
      return { kind: 'git', cloneUrl: pr.headCloneUrl, sha: pr.headSha };
    }
    // Private source: the trusted side downloads the tarball and streams bytes into the Sprite.
    const { owner, repo } = splitRepo(pr.headRepoFullName);
    const gh = await this.client(pr.repoFullName);
    const res = await gh.repos.downloadTarballArchive({ owner, repo, ref: pr.headSha });
    return { kind: 'tarball', data: Buffer.from(res.data as ArrayBuffer), sha: pr.headSha };
  }
}

export class OctokitWriteConnector implements GitHubWriteConnector {
  constructor(
    private readonly broker: GitHubCredentialBroker,
    private readonly log: Logger,
  ) {}

  get mode(): 'github-app' | 'token' {
    return this.broker.mode;
  }

  rememberInstallation(repoFullName: string, installationId: number): void {
    this.broker.rememberInstallation(repoFullName, installationId);
  }

  private client(repoFullName: string): Promise<Octokit> {
    return this.broker.octokit(repoFullName, WRITE_SCOPE);
  }

  async postComment(repoFullName: string, issueNumber: number, body: string): Promise<number> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
    const { data } = await gh.issues.createComment({ owner, repo, issue_number: issueNumber, body });
    return data.id;
  }

  async updateComment(repoFullName: string, commentId: number, body: string): Promise<void> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
    await gh.issues.updateComment({ owner, repo, comment_id: commentId, body });
  }

  async addReaction(repoFullName: string, commentId: number, reaction: '+1' | 'eyes' | 'rocket' | 'confused'): Promise<void> {
    const { owner, repo } = splitRepo(repoFullName);
    const gh = await this.client(repoFullName);
    try {
      await gh.reactions.createForIssueComment({ owner, repo, comment_id: commentId, content: reaction });
    } catch (err) {
      this.log.debug({ err }, 'failed to add reaction');
    }
  }

  async commitFiles(req: CommitFilesRequest): Promise<string> {
    const { owner, repo } = splitRepo(req.repoFullName);
    const gh = await this.client(req.repoFullName);
    const ref = `heads/${req.branch}`;
    const { data: refData } = await gh.git.getRef({ owner, repo, ref });
    if (refData.object.sha !== req.expectedHeadSha) throw new StaleHeadError(req.expectedHeadSha, refData.object.sha);

    const { data: headCommit } = await gh.git.getCommit({ owner, repo, commit_sha: req.expectedHeadSha });
    const { data: baseTree } = await gh.git.getTree({ owner, repo, tree_sha: headCommit.tree.sha, recursive: 'true' });
    const modes = new Map(baseTree.tree.map((t) => [t.path ?? '', t.mode ?? '100644']));

    const entries: Array<{ path: string; mode: '100644' | '100755'; type: 'blob'; sha: string | null }> = [];
    for (const file of req.files) {
      const existingMode = modes.get(file.path);
      const mode: '100644' | '100755' = existingMode === '100755' ? '100755' : '100644';
      if (file.action === 'delete') {
        if (modes.has(file.path)) entries.push({ path: file.path, mode, type: 'blob', sha: null });
        continue;
      }
      const { data: blob } = await gh.git.createBlob({
        owner,
        repo,
        content: Buffer.from(file.content ?? '', 'utf8').toString('base64'),
        encoding: 'base64',
      });
      entries.push({ path: file.path, mode, type: 'blob', sha: blob.sha });
    }

    const { data: tree } = await gh.git.createTree({ owner, repo, base_tree: headCommit.tree.sha, tree: entries });
    const { data: commit } = await gh.git.createCommit({
      owner,
      repo,
      message: req.message,
      tree: tree.sha,
      parents: [req.expectedHeadSha],
    });
    await gh.git.updateRef({ owner, repo, ref, sha: commit.sha, force: false });
    this.log.info({ repo: req.repoFullName, branch: req.branch, commit: commit.sha }, 'verified patch committed');
    return commit.sha;
  }
}

/* -------------------------------------------------------------------------------------------------
 * Local GitHub simulator — LOCAL_SANDBOX_MODE
 * -----------------------------------------------------------------------------------------------*/

export interface SimulatedPullRequest {
  repoFullName: string;
  number: number;
  title: string;
  body: string;
  author: string;
  baseRef: string;
  headRef: string;
  headSha: string;
  baseFiles: Record<string, string>;
  headFiles: Record<string, string>;
  commits: CommitPatch[];
  state: 'open' | 'closed';
}

export interface TimelineEntry {
  id: number;
  repoFullName: string;
  prNumber: number;
  kind: 'comment' | 'commit' | 'reaction';
  author: string;
  body: string;
  createdAt: string;
  updatedAt: string;
}

export class LocalGitHubSimulator {
  private readonly prs = new Map<string, SimulatedPullRequest>();
  private readonly timeline: TimelineEntry[] = [];
  private readonly permissions = new Map<string, RepoPermission>();
  private nextId = 1000;

  constructor(readonly botLogin: string) {}

  private key(repoFullName: string, n: number): string {
    return `${repoFullName.toLowerCase()}#${n}`;
  }

  upsertPullRequest(pr: SimulatedPullRequest): void {
    this.prs.set(this.key(pr.repoFullName, pr.number), pr);
  }

  getPullRequest(repoFullName: string, n: number): SimulatedPullRequest {
    const pr = this.prs.get(this.key(repoFullName, n));
    if (!pr) throw Object.assign(new Error(`simulated PR ${repoFullName}#${n} not found`), { status: 404 });
    return pr;
  }

  nextPrNumber(repoFullName: string): number {
    let max = 0;
    for (const pr of this.prs.values()) if (pr.repoFullName === repoFullName) max = Math.max(max, pr.number);
    return max + 1;
  }

  setPermission(repoFullName: string, user: string, perm: RepoPermission): void {
    this.permissions.set(`${repoFullName.toLowerCase()}:${user.toLowerCase()}`, perm);
  }

  permissionOf(repoFullName: string, user: string): RepoPermission {
    return this.permissions.get(`${repoFullName.toLowerCase()}:${user.toLowerCase()}`) ?? 'read';
  }

  addTimeline(entry: Omit<TimelineEntry, 'id' | 'createdAt' | 'updatedAt'>): TimelineEntry {
    const now = new Date().toISOString();
    const full: TimelineEntry = { ...entry, id: this.nextId++, createdAt: now, updatedAt: now };
    this.timeline.push(full);
    if (this.timeline.length > 500) this.timeline.shift();
    return full;
  }

  updateTimeline(id: number, body: string): void {
    const e = this.timeline.find((t) => t.id === id);
    if (!e) throw Object.assign(new Error(`comment ${id} not found`), { status: 404 });
    e.body = body;
    e.updatedAt = new Date().toISOString();
  }

  getTimeline(repoFullName?: string, prNumber?: number): TimelineEntry[] {
    return this.timeline.filter(
      (t) => (!repoFullName || t.repoFullName === repoFullName) && (prNumber === undefined || t.prNumber === prNumber),
    );
  }
}

export function fakeSha(seed: string): string {
  return createHash('sha1').update(seed).digest('hex');
}

export function buildGitDiff(before: Record<string, string>, after: Record<string, string>): string {
  const paths = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const chunks: string[] = [];
  for (const path of paths) {
    const a = before[path];
    const b = after[path];
    if (a === b) continue;
    const patch = createTwoFilesPatch(
      a === undefined ? '/dev/null' : `a/${path}`,
      b === undefined ? '/dev/null' : `b/${path}`,
      a ?? '',
      b ?? '',
      undefined,
      undefined,
      { context: 3 },
    )
      .split('\n')
      .filter((l) => !l.startsWith('====='))
      .join('\n');
    chunks.push(`diff --git a/${path} b/${path}\n${patch.replace(/^Index:.*\n/, '')}`);
  }
  return chunks.join('\n');
}

export class LocalReadOnlyConnector implements ReadOnlyGitHubConnector {
  readonly mode = 'local' as const;
  constructor(private readonly sim: LocalGitHubSimulator) {}

  rememberInstallation(): void {
    /* no-op locally */
  }

  async getPullRequest(repoFullName: string, prNumber: number): Promise<PrContext> {
    const pr = this.sim.getPullRequest(repoFullName, prNumber);
    const { owner, repo } = splitRepo(repoFullName);
    return {
      owner,
      repo,
      repoFullName,
      number: pr.number,
      title: pr.title,
      body: pr.body,
      author: pr.author,
      headSha: pr.headSha,
      headRef: pr.headRef,
      headRepoFullName: repoFullName,
      headCloneUrl: `local://${repoFullName}`,
      baseRef: pr.baseRef,
      isFork: false,
      isPrivate: true,
      maintainerCanModify: true,
      state: pr.state,
    };
  }

  async getPullRequestDiff(repoFullName: string, prNumber: number): Promise<string> {
    const pr = this.sim.getPullRequest(repoFullName, prNumber);
    return buildGitDiff(pr.baseFiles, pr.headFiles);
  }

  async listCommitPatches(repoFullName: string, prNumber: number): Promise<CommitPatch[]> {
    return this.sim.getPullRequest(repoFullName, prNumber).commits;
  }

  async getFileContent(repoFullName: string, path: string, ref: string): Promise<string | null> {
    for (const n of [...Array(this.sim.nextPrNumber(repoFullName)).keys()].slice(1)) {
      const pr = this.sim.getPullRequest(repoFullName, n);
      if (pr.headSha === ref) return pr.headFiles[path] ?? null;
    }
    return null;
  }

  async getRepoPermission(repoFullName: string, username: string): Promise<RepoPermission> {
    return this.sim.permissionOf(repoFullName, username);
  }

  async getSourceDelivery(pr: PrContext): Promise<SourceDelivery> {
    const sim = this.sim.getPullRequest(pr.repoFullName, pr.number);
    return { kind: 'files', files: { ...sim.headFiles }, sha: sim.headSha };
  }
}

export class LocalWriteConnector implements GitHubWriteConnector {
  readonly mode = 'local' as const;
  constructor(private readonly sim: LocalGitHubSimulator) {}

  rememberInstallation(): void {
    /* no-op locally */
  }

  private prNumberForComment(repoFullName: string, issueNumber: number): number {
    return issueNumber;
  }

  async postComment(repoFullName: string, issueNumber: number, body: string): Promise<number> {
    return this.sim.addTimeline({
      repoFullName,
      prNumber: this.prNumberForComment(repoFullName, issueNumber),
      kind: 'comment',
      author: this.sim.botLogin,
      body,
    }).id;
  }

  async updateComment(_repoFullName: string, commentId: number, body: string): Promise<void> {
    this.sim.updateTimeline(commentId, body);
  }

  async addReaction(repoFullName: string, commentId: number, reaction: string): Promise<void> {
    const target = this.sim.getTimeline(repoFullName).find((t) => t.id === commentId);
    this.sim.addTimeline({
      repoFullName,
      prNumber: target?.prNumber ?? 0,
      kind: 'reaction',
      author: this.sim.botLogin,
      body: `reacted :${reaction}: to comment #${commentId}`,
    });
  }

  async commitFiles(req: CommitFilesRequest): Promise<string> {
    const prs = [...Array(this.sim.nextPrNumber(req.repoFullName)).keys()]
      .slice(1)
      .map((n) => this.sim.getPullRequest(req.repoFullName, n));
    const pr = prs.find((p) => p.headRef === req.branch && p.state === 'open');
    if (!pr) throw new Error(`no open simulated PR for branch ${req.branch}`);
    if (pr.headSha !== req.expectedHeadSha) throw new StaleHeadError(req.expectedHeadSha, pr.headSha);
    const before = { ...pr.headFiles };
    const after = { ...pr.headFiles };
    for (const f of req.files) {
      if (f.action === 'delete') delete after[f.path];
      else after[f.path] = f.content ?? '';
    }
    const sha = fakeSha(`${pr.headSha}:${req.message}:${Date.now()}`);
    const diff = buildGitDiff(before, after);
    pr.commits = [
      ...pr.commits,
      {
        sha,
        message: req.message,
        author: this.sim.botLogin,
        files: req.files.map((f) => ({
          filename: f.path,
          patch: diff
            .split(/(?=^diff --git )/m)
            .find((c) => c.startsWith(`diff --git a/${f.path} `))
            ?.split('\n')
            .filter((l) => !l.startsWith('diff --git') && !l.startsWith('---') && !l.startsWith('+++'))
            .join('\n') ?? '',
        })),
      },
    ];
    pr.headFiles = after;
    pr.headSha = sha;
    this.sim.addTimeline({
      repoFullName: req.repoFullName,
      prNumber: pr.number,
      kind: 'commit',
      author: this.sim.botLogin,
      body: `${sha.slice(0, 7)} ${req.message.split('\n')[0]}`,
    });
    return sha;
  }
}

/* -------------------------------------------------------------------------------------------------
 * Factory
 * -----------------------------------------------------------------------------------------------*/

export interface GitHubConnectors {
  read: ReadOnlyGitHubConnector;
  write: GitHubWriteConnector;
  simulator: LocalGitHubSimulator | null;
}

export function createGitHubConnectors(config: AppConfig, log: Logger): GitHubConnectors {
  const hasRealCreds = Boolean(
    (config.github.appId && config.github.appPrivateKey) || (config.github.readToken && config.github.writeToken),
  );
  if (config.localSandboxMode && !hasRealCreds) {
    const sim = new LocalGitHubSimulator(config.github.botLogin);
    log.warn('No GitHub credentials configured — using the local GitHub simulator.');
    return { read: new LocalReadOnlyConnector(sim), write: new LocalWriteConnector(sim), simulator: sim };
  }
  const readBroker = new GitHubCredentialBroker(config.github, log.child({ connector: 'github-read' }));
  const writeBroker = new GitHubCredentialBroker(config.github, log.child({ connector: 'github-write' }));
  return {
    read: new OctokitReadOnlyConnector(readBroker, log.child({ connector: 'github-read' })),
    write: new OctokitWriteConnector(writeBroker, log.child({ connector: 'github-write' })),
    simulator: null,
  };
}
