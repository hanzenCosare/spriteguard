import { createHash } from 'node:crypto';
import type { AppConfig, ApproverPermission } from './config.js';
import type { EmbeddingClient, Store } from './db/client.js';
import {
  StaleHeadError,
  type CommitFilesRequest,
  type GitHubWriteConnector,
  type ReadOnlyGitHubConnector,
  type RepoPermission,
  type SourceDelivery,
} from './fly/githubConnector.js';
import type { SpriteManager } from './fly/spriteManager.js';
import {
  formatApprovalDenied,
  formatApprovalSuccess,
  formatAuditError,
  formatAuditReport,
  formatQaReply,
} from './github/reportFormatter.js';
import type { Logger } from './logger.js';
import { runEgressProbe, scanWorkspaceFiles } from './scanner/egressProbe.js';
import { OpusAuditor } from './scanner/opusAuditor.js';
import {
  dedupeLeaks,
  isEnvFilePath,
  isScannablePath,
  parseUnifiedDiff,
  RedactionVault,
  scanCommitPatchesRaw,
  scanUnifiedDiffRaw,
  toPublicLeak,
  type RawSecretMatch,
} from './scanner/secretScanner.js';
import type {
  EgressReport,
  PatchRecord,
  PatchStatus,
  PrContext,
  ProposedPatch,
  ScanRecord,
  ScanReport,
  ScanStatus,
  StoredFinding,
} from './types.js';

/**
 * Trusted Orchestrator & Split-Connector Publisher.
 *
 * Enforces the zero-trust boundary:
 *  - Only ReadOnlyGitHubConnector is used during cloning & scanning; no raw tokens enter Sprites.
 *  - Only TrustedPublisher holds GitHubWriteConnector, and it only commits patches after
 *    maintainer approval and SHA-256 verification.
 */

const PERMISSION_RANK: Record<RepoPermission, number> = {
  admin: 4,
  maintain: 3,
  write: 2,
  triage: 1,
  read: 0,
  none: 0,
};

function shellQuote(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export class TrustedPublisher {
  constructor(private readonly write: GitHubWriteConnector) {}

  rememberInstallation(repoFullName: string, installationId: number): void {
    this.write.rememberInstallation(repoFullName, installationId);
  }

  postComment(repoFullName: string, prNumber: number, body: string): Promise<number> {
    return this.write.postComment(repoFullName, prNumber, body);
  }

  addReaction(
    repoFullName: string,
    commentId: number,
    reaction: '+1' | 'eyes' | 'rocket' | 'confused',
  ): Promise<void> {
    return this.write.addReaction(repoFullName, commentId, reaction);
  }

  publishVerifiedPatch(req: CommitFilesRequest): Promise<string> {
    return this.write.commitFiles(req);
  }
}

export interface ApprovalOutcome {
  ok: boolean;
  commitSha?: string;
  reason?: string;
  scanId?: string;
}

export interface QuestionOutcome {
  ok: boolean;
  answer?: string;
  commentId?: number;
  reason?: string;
}

export class AuditOrchestrator {
  private readonly queue: Array<() => void> = [];
  private activeCount = 0;
  private readonly inflightPrs = new Set<string>();
  private reaperTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
    private readonly embeddings: EmbeddingClient,
    private readonly sprites: SpriteManager,
    private readonly readConnector: ReadOnlyGitHubConnector,
    readonly publisher: TrustedPublisher,
    private readonly auditor: OpusAuditor,
    private readonly log: Logger,
  ) {
    this.sprites.onStateChange(async (spriteName, state) => {
      await this.store.updateSpriteStateByName(spriteName, state);
    });
  }

  startReaper(): void {
    if (this.reaperTimer) return;
    this.reaperTimer = setInterval(() => {
      void this.reapStaleSprites().catch((err) => {
        this.log.warn({ err }, 'stale sprite reaper pass failed');
      });
    }, 15 * 60_000);
    this.reaperTimer.unref();
  }

  stopReaper(): void {
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }
  }

  async reapStaleSprites(): Promise<number> {
    const stale = await this.store.listStaleSprites(this.config.sprites.ttlHours);
    let destroyed = 0;
    for (const scan of stale) {
      if (!scan.spriteName) continue;
      try {
        await this.sprites.destroy(scan.spriteName);
        if (scan.status === 'awaiting_approval' || scan.status === 'needs_review') {
          await this.store.updateScan(scan.id, {
            spriteState: 'destroyed',
            error: 'Sprite TTL expired before approval',
          });
        }
        destroyed++;
      } catch (err) {
        this.log.warn({ err, spriteName: scan.spriteName }, 'failed to destroy stale sprite');
      }
    }
    return destroyed;
  }

  private withConcurrencyLimit<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const start = () => {
        this.activeCount++;
        void fn()
          .then(resolve, reject)
          .finally(() => {
            this.activeCount--;
            const next = this.queue.shift();
            if (next) next();
          });
      };
      if (this.activeCount < this.config.audit.maxConcurrent) {
        start();
      } else {
        this.queue.push(start);
      }
    });
  }

  enqueuePullRequestAudit(repoFullName: string, prNumber: number): { accepted: boolean } {
    const prKey = `${repoFullName.toLowerCase()}#${prNumber}`;
    if (this.inflightPrs.has(prKey)) {
      this.log.info({ repoFullName, prNumber }, 'audit already queued/running for PR; skipping duplicate trigger');
      return { accepted: false };
    }
    this.inflightPrs.add(prKey);
    void this.withConcurrencyLimit(() => this.runPullRequestAudit(repoFullName, prNumber))
      .catch((err) => {
        this.log.error({ err, repoFullName, prNumber }, 'background PR audit failed');
      })
      .finally(() => {
        this.inflightPrs.delete(prKey);
      });
    return { accepted: true };
  }

  async runPullRequestAudit(repoFullName: string, prNumber: number): Promise<ScanRecord> {
    const timings: Record<string, number> = {};
    const t0 = Date.now();

    const pr = await this.readConnector.getPullRequest(repoFullName, prNumber);
    if (pr.state === 'closed') {
      throw new Error(`PR ${repoFullName}#${prNumber} is closed`);
    }

    const rawDiff = await this.readConnector.getPullRequestDiff(repoFullName, prNumber);
    const commits = await this.readConnector.listCommitPatches(repoFullName, prNumber);
    timings.githubReadMs = Date.now() - t0;

    let scan = await this.store.createScan({
      repoFullName: pr.repoFullName,
      prNumber: pr.number,
      headSha: pr.headSha,
      headRef: pr.headRef,
      headRepoFullName: pr.headRepoFullName,
      baseRef: pr.baseRef,
      prTitle: pr.title,
      prAuthor: pr.author,
    });

    const superseded = await this.store.supersedePriorScans(pr.repoFullName, pr.number, scan.id);
    for (const old of superseded) {
      if (old.spriteName && old.spriteState !== 'destroyed' && old.spriteState !== 'none') {
        await this.sprites.destroy(old.spriteName).catch((err) => {
          this.log.warn({ err, spriteName: old.spriteName }, 'failed to destroy superseded sprite');
        });
      }
    }

    const spriteName = this.sprites.nameFor(pr.repoFullName, pr.number, pr.headSha);
    scan =
      (await this.store.updateScan(scan.id, {
        status: 'running',
        spriteName,
        spriteState: 'creating',
      })) ?? scan;

    let keepSpriteAsleep = false;
    let checkpointId: string | null = null;

    try {
      const tProvision = Date.now();
      await this.sprites.provision(spriteName, [
        `repo:${pr.repoFullName.replace(/[^a-zA-Z0-9._-]/g, '_')}`,
        `pr:${pr.number}`,
        `sha:${pr.headSha.slice(0, 7)}`,
      ]);
      const delivery = await this.readConnector.getSourceDelivery(pr);
      await this.deliverSourceIntoSprite(spriteName, pr, delivery);
      const preAuditCheckpointId = await this.sprites.checkpoint(spriteName, 'pre-audit');
      checkpointId = preAuditCheckpointId;
      timings.spriteProvisionMs = Date.now() - tProvision;

      // Layer A — Static & Build Secret Scanner (diff + commits + .env* files)
      const tLayerA = Date.now();
      const diffLeaks = scanUnifiedDiffRaw(rawDiff, 'diff');
      const commitLeaks = scanCommitPatchesRaw(commits);
      const envLeaks = await scanWorkspaceFiles(this.sprites, spriteName, ['env']);
      timings.layerAMs = Date.now() - tLayerA;

      // Layer B — Network Policy + Runtime & Egress Probe + Build Output Scan
      const tLayerB = Date.now();
      if (this.config.sprites.enforceEgressPolicy) {
        await this.sprites.setNetworkPolicy(spriteName, this.config.sprites.egressAllowlist);
      }
      const allowLocalExec = this.config.localAllowUntrustedExec || this.readConnector.mode === 'local';
      const egressProbe = await runEgressProbe({
        sprites: this.sprites,
        spriteName,
        allowlist: this.config.sprites.egressAllowlist,
        installTimeoutSec: this.config.audit.installTimeoutSec,
        testTimeoutSec: this.config.audit.testTimeoutSec,
        allowLocalExec,
        log: this.log,
      });
      const buildLeaks = await scanWorkspaceFiles(this.sprites, spriteName, ['build']);
      timings.layerBMs = Date.now() - tLayerB;

      const allRawLeaks = dedupeLeaks<RawSecretMatch>([
        ...diffLeaks,
        ...commitLeaks,
        ...envLeaks,
        ...buildLeaks,
        ...egressProbe.rawRuntimeLeaks,
      ]);
      const vault = new RedactionVault();
      vault.registerAll(allRawLeaks);

      const staticLeaks = allRawLeaks.filter((l) => l.source !== 'runtime_output').map(toPublicLeak);
      const redactedRuntimeLeaks = egressProbe.rawRuntimeLeaks.map(toPublicLeak);
      const egress: EgressReport = {
        projectType: egressProbe.projectType,
        commands: egressProbe.commands.map((c) => ({
          ...c,
          stdoutTail: vault.redact(c.stdoutTail),
          stderrTail: vault.redact(c.stderrTail),
        })),
        domains: egressProbe.domains,
        rawIps: egressProbe.rawIps,
        runtimeLeaks: redactedRuntimeLeaks,
        canaryExfiltrations: egressProbe.canaryExfiltrations,
        ...(egressProbe.skipped ? { skipped: egressProbe.skipped } : {}),
      };

      const clippedDiff =
        rawDiff.length > this.config.audit.maxDiffChars
          ? `${rawDiff.slice(0, this.config.audit.maxDiffChars)}\n…[diff truncated at ${this.config.audit.maxDiffChars} chars]…`
          : rawDiff;
      const redactedDiff = vault.redact(clippedDiff);

      // Layer C — Semantic Memory (Neon pgvector) + Claude Opus Audit
      const tLayerC = Date.now();
      const queryText = [
        pr.title,
        ...parseUnifiedDiff(rawDiff).map((f) => f.path),
        ...staticLeaks.map((l) => `secret_leak ${l.severity} ${l.ruleName} ${l.file}`),
        ...egress.domains.filter((d) => d.flagged).map((d) => `malicious_egress ${d.host}`),
      ].join(' ');
      const queryVec = await this.embeddings.embed(queryText);
      const pastIncidents = await this.store.searchSimilarFindings(pr.repoFullName, queryVec, {
        limit: 5,
        excludeScanId: scan.id,
        minSimilarity: 0.2,
      });

      const audit = await this.auditor.auditPullRequest({
        pr,
        redactedDiff,
        staticLeaks,
        egress,
        pastIncidents,
      });
      timings.layerCMs = Date.now() - tLayerC;

      // Autonomous Patch Generation & Verification inside Sprite
      const tPatch = Date.now();
      let proposedPatch: ProposedPatch | null = null;
      let patchRecord: PatchRecord | null = null;

      const needsRemediation =
        this.config.audit.autoPatch &&
        (audit.patchRecommended ||
          staticLeaks.length > 0 ||
          egress.domains.some((d) => d.flagged) ||
          egress.canaryExfiltrations.length > 0);

      if (needsRemediation) {
        const authFiles = await this.fetchAuthoritativeFiles(pr, rawDiff, allRawLeaks);
        proposedPatch = await this.auditor.generatePatch({
          pr,
          audit,
          redactedDiff,
          staticLeaks,
          rawLeaks: allRawLeaks,
          egress,
          authoritativeFiles: authFiles,
          vault,
        });

        if (proposedPatch) {
          let verification = await this.auditor.verifyPatchInSprite({
            sprites: this.sprites,
            spriteName,
            preAuditCheckpointId,
            patch: proposedPatch,
            rawLeaks: allRawLeaks,
            testsBefore: egressProbe.testsBefore,
            allowlist: this.config.sprites.egressAllowlist,
            testTimeoutSec: this.config.audit.testTimeoutSec,
            allowLocalExec,
          });

          // 1 automatic self-repair retry if an AI-generated patch broke tests or left leaks
          if (verification.status === 'failed' && proposedPatch.generator === 'claude' && this.auditor.hasAi) {
            const failureNote = [
              `Verification status: ${verification.status}`,
              `Tests after: ${verification.testsAfter.summary}`,
              `Remaining leaks: ${verification.remainingLeaks.length}`,
              `Flagged egress after: ${verification.flaggedEgressAfter.join(', ') || 'none'}`,
              ...verification.notes,
            ].join('\n');

            const retried = await this.auditor.generatePatch({
              pr,
              audit,
              redactedDiff,
              staticLeaks,
              rawLeaks: allRawLeaks,
              egress,
              authoritativeFiles: authFiles,
              vault,
              pastFailureNote: failureNote,
            });
            if (retried) {
              const retriedVer = await this.auditor.verifyPatchInSprite({
                sprites: this.sprites,
                spriteName,
                preAuditCheckpointId,
                patch: retried,
                rawLeaks: allRawLeaks,
                testsBefore: egressProbe.testsBefore,
                allowlist: this.config.sprites.egressAllowlist,
                testTimeoutSec: this.config.audit.testTimeoutSec,
                allowLocalExec,
              });
              proposedPatch = retried;
              verification = retriedVer;
            }
          }

          proposedPatch.verification = verification;
          const patchStatus: PatchStatus =
            verification.status === 'verified'
              ? 'verified'
              : verification.status === 'verified_with_warnings'
                ? 'verified_with_warnings'
                : 'failed';

          // Store verified patch manifest inside Sprite for SHA-256 cross-check on wake
          const manifestPath = `${this.sprites.paths(spriteName).tools}/verified-patch.json`;
          await this.sprites.writeFile(
            spriteName,
            manifestPath,
            JSON.stringify({
              scanId: scan.id,
              headSha: pr.headSha,
              diffSha256: proposedPatch.diffSha256,
              status: patchStatus,
              verifiedAt: verification.verifiedAt,
            }),
            0o644,
          );

          patchRecord = await this.store.savePatch({
            scanId: scan.id,
            summary: proposedPatch.summary,
            files: proposedPatch.files,
            diff: proposedPatch.diff,
            diffSha256: proposedPatch.diffSha256,
            verification,
            postMergeActions: proposedPatch.postMergeActions,
            generator: proposedPatch.generator,
            status: patchStatus,
          });
        }
      }
      timings.patchAndVerifyMs = Date.now() - tPatch;

      // Sleep Sprite if patch is awaiting human approval; otherwise destroy immediately
      let finalStatus: ScanStatus;
      if (patchRecord && (patchRecord.status === 'verified' || patchRecord.status === 'verified_with_warnings')) {
        checkpointId = await this.sprites.hibernate(spriteName, 'verified-patch');
        keepSpriteAsleep = true;
        finalStatus = 'awaiting_approval';
      } else {
        await this.sprites.destroy(spriteName);
        finalStatus = audit.findings.length === 0 ? 'clean' : 'needs_review';
      }

      // Persist semantic findings into Neon pgvector
      if (audit.findings.length > 0) {
        const embedInputs = audit.findings.map(
          (f) => `${f.category} ${f.severity} ${f.title} ${f.file} ${f.exploitability} ${f.remediation}`,
        );
        const vectors = await this.embeddings.embedBatch(embedInputs);
        const stored: StoredFinding[] = audit.findings.map((f, i) => ({
          scanId: scan.id,
          repoFullName: pr.repoFullName,
          prNumber: pr.number,
          finding: f,
          fingerprint: createHash('sha256')
            .update(`${f.category}:${f.file}:${f.line}:${f.title}`)
            .digest('hex')
            .slice(0, 16),
          embedding: vectors[i] ?? queryVec,
        }));
        await this.store.saveFindings(stored);
      }

      timings.totalMs = Date.now() - t0;

      const report: ScanReport = {
        scanId: scan.id,
        repoFullName: pr.repoFullName,
        prNumber: pr.number,
        prTitle: pr.title,
        headSha: pr.headSha,
        generatedAt: new Date().toISOString(),
        audit,
        staticLeaks,
        egress,
        pastIncidents,
        patch: proposedPatch
          ? {
              summary: proposedPatch.summary,
              files: proposedPatch.files.map(({ content: _c, ...rest }) => rest),
              diff: proposedPatch.diff,
              diffSha256: proposedPatch.diffSha256,
              postMergeActions: proposedPatch.postMergeActions,
              generator: proposedPatch.generator,
              verification: proposedPatch.verification,
            }
          : null,
        timings,
        sandbox: {
          driver: this.sprites.driver.kind,
          spriteName,
        },
      };

      const flaggedEgressCount = egress.domains.filter((d) => d.flagged).length;
      scan =
        (await this.store.updateScan(scan.id, {
          status: finalStatus,
          riskScore: audit.riskScore,
          severity: audit.severity,
          findingsCount: audit.findings.length,
          secretsCount: staticLeaks.length + egress.runtimeLeaks.length,
          flaggedEgressCount,
          egressDomains: egress.domains,
          checkpointId,
          spriteState: keepSpriteAsleep ? 'sleeping' : 'destroyed',
          report,
          completedAt: new Date().toISOString(),
        })) ?? scan;

      const reportMarkdown = formatAuditReport(scan, report, patchRecord, {
        ...(this.config.publicUrl ? { dashboardUrl: this.config.publicUrl } : {}),
      });
      const commentId = await this.publisher.postComment(pr.repoFullName, pr.number, reportMarkdown);

      scan =
        (await this.store.updateScan(scan.id, {
          reportMarkdown,
          commentId,
        })) ?? scan;

      this.log.info(
        {
          scanId: scan.id,
          repo: pr.repoFullName,
          pr: pr.number,
          riskScore: audit.riskScore,
          severity: audit.severity,
          status: finalStatus,
          spriteState: scan.spriteState,
        },
        'PR audit completed',
      );
      return scan;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.log.error({ err, scanId: scan.id, repo: pr.repoFullName, pr: pr.number }, 'PR audit failed');
      await this.sprites.destroy(spriteName).catch(() => {});
      await this.store.updateScan(scan.id, {
        status: 'failed',
        spriteState: 'destroyed',
        error: msg,
        completedAt: new Date().toISOString(),
      });
      await this.publisher
        .postComment(pr.repoFullName, pr.number, formatAuditError(pr.repoFullName, pr.number, pr.headSha, msg))
        .catch(() => {});
      throw err;
    }
  }

  private async deliverSourceIntoSprite(spriteName: string, pr: PrContext, delivery: SourceDelivery): Promise<void> {
    const paths = this.sprites.paths(spriteName);
    if (delivery.kind === 'git') {
      const cmd = [
        `rm -rf ${shellQuote(paths.repo)}`,
        `git init ${shellQuote(paths.repo)}`,
        `cd ${shellQuote(paths.repo)}`,
        `git remote add origin ${shellQuote(delivery.cloneUrl)}`,
        `git fetch --depth 1 origin ${shellQuote(delivery.sha)}`,
        `git checkout --detach FETCH_HEAD`,
      ].join(' && ');
      const res = await this.sprites.exec(spriteName, cmd, { timeoutMs: 180_000 });
      if (res.exitCode !== 0) {
        throw new Error(`failed to clone ${delivery.cloneUrl} at ${delivery.sha}: ${res.stderr}`);
      }
      return;
    }

    if (delivery.kind === 'tarball') {
      const tarPath = `${paths.tools}/source.tar.gz`;
      await this.sprites.writeFile(spriteName, tarPath, delivery.data, 0o600);
      const res = await this.sprites.exec(
        spriteName,
        `rm -rf ${shellQuote(paths.repo)} && mkdir -p ${shellQuote(paths.repo)} && tar -xzf ${shellQuote(tarPath)} --strip-components=1 -C ${shellQuote(paths.repo)} && rm -f ${shellQuote(tarPath)}`,
        { timeoutMs: 180_000 },
      );
      if (res.exitCode !== 0) {
        throw new Error(`failed to extract repository tarball: ${res.stderr}`);
      }
      return;
    }

    for (const [relPath, content] of Object.entries(delivery.files)) {
      await this.sprites.writeFile(spriteName, `${paths.repo}/${relPath}`, content, 0o644);
    }
  }

  private async fetchAuthoritativeFiles(
    pr: PrContext,
    rawDiff: string,
    rawLeaks: RawSecretMatch[],
  ): Promise<Record<string, string>> {
    const candidates = new Set<string>(['.gitignore', 'package.json']);
    for (const df of parseUnifiedDiff(rawDiff)) {
      if (!df.deleted && (isScannablePath(df.path) || isEnvFilePath(df.path))) candidates.add(df.path);
    }
    for (const leak of rawLeaks) {
      if (!leak.file.startsWith('<')) candidates.add(leak.file);
    }

    const out: Record<string, string> = {};
    for (const path of [...candidates].slice(0, 30)) {
      try {
        const content = await this.readConnector.getFileContent(pr.repoFullName, path, pr.headSha);
        if (content !== null && content.length <= 250_000) {
          out[path] = content;
        }
      } catch (err) {
        this.log.debug({ err, path }, 'failed to read authoritative file content');
      }
    }
    return out;
  }

  async handleApproval(
    repoFullName: string,
    prNumber: number,
    approver: string,
    commentId?: number,
  ): Promise<ApprovalOutcome> {
    if (commentId) {
      await this.publisher.addReaction(repoFullName, commentId, 'eyes').catch(() => {});
    }

    const perm = await this.readConnector.getRepoPermission(repoFullName, approver);
    const minPerm: ApproverPermission = this.config.github.approverMinPermission;
    if (PERMISSION_RANK[perm] < PERMISSION_RANK[minPerm]) {
      const reason = `User @${approver} has \`${perm}\` permission on ${repoFullName}, but \`${minPerm}\` or higher is required to approve SpriteGuard patches.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason };
    }

    const scan = await this.store.getLatestScanForPr(repoFullName, prNumber);
    if (!scan) {
      const reason = `No completed SpriteGuard audit was found for ${repoFullName}#${prNumber}.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason };
    }

    const existingPatch = await this.store.getPatch(scan.id);
    if (!existingPatch) {
      const reason = `Scan \`${scan.id.slice(0, 8)}\` has no generated patch to approve.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }
    if (existingPatch.status === 'pushed') {
      const reason = `Patch for scan \`${scan.id.slice(0, 8)}\` was already committed (\`${existingPatch.commitSha ?? 'unknown'}\`).`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }
    if (existingPatch.status !== 'verified' && existingPatch.status !== 'verified_with_warnings') {
      const reason = `Patch is in status \`${existingPatch.status}\` and cannot be auto-committed.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }

    const livePr = await this.readConnector.getPullRequest(repoFullName, prNumber);
    if (livePr.state !== 'open') {
      const reason = `PR #${prNumber} is closed.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }
    if (livePr.headSha !== scan.headSha) {
      const reason = `PR head moved from \`${scan.headSha.slice(0, 7)}\` to \`${livePr.headSha.slice(0, 7)}\`. Wait for the new commit's audit or comment \`/spriteguard rescan\`.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }
    if (livePr.isFork && !livePr.maintainerCanModify) {
      const reason = `This PR originates from a fork where maintainers do not have write permission to push to \`${livePr.headRepoFullName}:${livePr.headRef}\`.`;
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }

    const claimed = await this.store.claimPatchApproval(scan.id, approver);
    if (!claimed) {
      const reason = 'Patch approval was already claimed by a concurrent request.';
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, reason));
      return { ok: false, reason, scanId: scan.id };
    }

    try {
      // Wake sleeping Sprite and cross-verify the stored patch manifest SHA-256
      if (scan.spriteName && (await this.sprites.exists(scan.spriteName))) {
        await this.sprites.wake(scan.spriteName, scan.checkpointId ?? undefined);
        const manifestPath = `${this.sprites.paths(scan.spriteName).tools}/verified-patch.json`;
        const check = await this.sprites.exec(scan.spriteName, `cat ${shellQuote(manifestPath)} 2>/dev/null || true`, {
          timeoutMs: 30_000,
        });
        if (check.stdout.trim()) {
          const parsed = JSON.parse(check.stdout.trim()) as { diffSha256?: string };
          if (parsed.diffSha256 && parsed.diffSha256 !== claimed.diffSha256) {
            throw new Error(
              `Patch integrity mismatch: Sprite manifest ${parsed.diffSha256} != DB ${claimed.diffSha256}`,
            );
          }
        }
      }

      // Commit strictly using the TrustedPublisher's GitHub Write Connector with DB-stored PatchFile[]
      const commitSha = await this.publisher.publishVerifiedPatch({
        repoFullName: livePr.headRepoFullName,
        branch: livePr.headRef,
        expectedHeadSha: livePr.headSha,
        message: `fix(security): apply SpriteGuard verified patch for #${prNumber}\n\n${claimed.summary}\n\nApproved-by: @${approver}\nSpriteGuard-Scan: ${scan.id}\nVerified-Diff-SHA256: ${claimed.diffSha256}`,
        files: claimed.files,
      });

      const pushedAt = new Date().toISOString();
      await this.store.updatePatch(scan.id, {
        status: 'pushed',
        commitSha,
        pushedAt,
      });
      await this.store.updateScan(scan.id, {
        status: 'pushed',
        spriteState: 'destroyed',
      });

      if (scan.spriteName) {
        await this.sprites.destroy(scan.spriteName).catch(() => {});
      }

      await this.publisher.postComment(repoFullName, prNumber, formatApprovalSuccess(scan, claimed, commitSha, approver));
      if (commentId) {
        await this.publisher.addReaction(repoFullName, commentId, 'rocket').catch(() => {});
      }
      this.log.info({ scanId: scan.id, repoFullName, prNumber, approver, commitSha }, 'approved patch pushed');
      return { ok: true, commitSha, scanId: scan.id };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const statusMsg = err instanceof StaleHeadError ? err.message : `Failed to commit patch: ${msg}`;
      await this.store.updatePatch(scan.id, { status: 'publish_failed' });
      await this.store.updateScan(scan.id, { status: 'publish_failed', error: statusMsg });
      if (scan.spriteName) {
        await this.sprites.destroy(scan.spriteName).catch(() => {});
      }
      await this.publisher.postComment(repoFullName, prNumber, formatApprovalDenied(approver, statusMsg));
      return { ok: false, reason: statusMsg, scanId: scan.id };
    }
  }

  async handleQuestion(
    repoFullName: string,
    prNumber: number,
    asker: string,
    question: string,
    commentId?: number,
  ): Promise<QuestionOutcome> {
    if (commentId) {
      await this.publisher.addReaction(repoFullName, commentId, 'eyes').catch(() => {});
    }

    const scan = await this.store.getLatestScanForPr(repoFullName, prNumber);
    if (!scan) {
      const reply = `@${asker} No SpriteGuard audit is available yet for **${repoFullName}#${prNumber}**. Comment \`/spriteguard rescan\` to trigger one.`;
      const postedId = await this.publisher.postComment(repoFullName, prNumber, reply);
      return { ok: false, reason: 'No scan found', answer: reply, commentId: postedId };
    }

    const patch = await this.store.getPatch(scan.id);
    const qVec = await this.embeddings.embed(question);
    const relatedIncidents = await this.store.searchSimilarFindings(repoFullName, qVec, {
      limit: 5,
      excludeScanId: scan.id,
      minSimilarity: 0.25,
    });

    const answer = await this.auditor.answerQuestion({
      scan,
      report: scan.report,
      patch,
      relatedIncidents,
      question,
      asker,
    });

    const formatted = formatQaReply(question, answer, scan);
    const postedId = await this.publisher.postComment(repoFullName, prNumber, formatted);
    if (commentId) {
      await this.publisher.addReaction(repoFullName, commentId, '+1').catch(() => {});
    }
    return { ok: true, answer, commentId: postedId };
  }

  async handlePullRequestClosed(repoFullName: string, prNumber: number): Promise<void> {
    const scans = await this.store.listScans({ repo: repoFullName, limit: 100 });
    for (const scan of scans) {
      if (scan.prNumber !== prNumber) continue;
      if (scan.spriteName && scan.spriteState !== 'destroyed' && scan.spriteState !== 'none') {
        await this.sprites.destroy(scan.spriteName).catch(() => {});
      }
      if (scan.status === 'awaiting_approval' || scan.status === 'needs_review') {
        await this.store.updateScan(scan.id, { status: 'closed', spriteState: 'destroyed' });
      }
    }
  }
}
