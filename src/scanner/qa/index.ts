import type { PastIncident, PatchRecord, ScanRecord, ScanReport } from '../../types.js';
import { RedactionVault, scanTextRaw } from '../secretScanner.js';
import { resolveEntities, sortFindingsByPriority } from './entities.js';
import {
  buildSuggestedQuestions,
  dispatchIntent,
  handleCleanShortCircuit,
  handleDisambiguation,
  handleOutOfScope,
  INTENT_SECTION_TITLE,
  type HandlerOutput,
} from './handlers.js';
import { resolveConversationalContext } from './memory.js';
import { normalizeQuery } from './normalize.js';
import { scoreIntents, selectWinningIntents } from './scorer.js';
import {
  DETERMINISTIC_BADGE,
  type ConversationTurn,
  type ConversationTurnMeta,
  type DeterministicAuditPayload,
  type DeterministicEgressEvent,
  type DeterministicFinding,
  type DeterministicQaResponse,
  type IntentId,
  type TurnOutcomeKind,
} from './types.js';

export * from './types.js';
export * from './normalize.js';
export * from './entities.js';
export * from './memory.js';
export * from './logParser.js';
export * from './remediation.js';
export * from './scorer.js';
export * from './handlers.js';

/**
 * Mandatory Final Post-Pass — Zero-Leak Redaction Invariant.
 * Guarantees raw secret literals never appear unmasked in any output
 * while preserving safe already-masked previews like `sk_l************4321`.
 */
const RAW_SECRET_PREFIX_PATTERNS: readonly RegExp[] = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{12,}\b/g,
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[0-9A-Za-z]{16,}\b/g,
  /\bgithub_pat_[0-9A-Za-z_]{20,}\b/g,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /\bsk-ant-[0-9A-Za-z_-]{16,}\b/g,
  /\bwhsec_[0-9A-Za-z]{20,}\b/g,
  /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/([^:\s/]+):([^@\s*]{6,})@/gi,
];

function maskLiteral(raw: string): string {
  if (raw.startsWith('-----BEGIN')) return '[REDACTED_PRIVATE_KEY]';
  if (raw.includes('://')) {
    return raw.replace(/:\/\/([^:\s/]+):([^@\s]+)@/, '://$1:[REDACTED_SECRET]@');
  }
  if (raw.length <= 10) return '[REDACTED_SECRET]';
  return `${raw.slice(0, 4)}************${raw.slice(-4)}`;
}

export function sanitizeZeroLeakOutput(text: string, maxChars = 4000): string {
  let out = text;

  // 1. Run Layer A scanner + RedactionVault over the entire rendered reply
  const rawMatches = scanTextRaw(out, {
    file: 'qa-reply.txt',
    source: 'runtime_output',
    entropy: false,
  });
  if (rawMatches.length > 0) {
    const vault = new RedactionVault();
    vault.registerAll(rawMatches);
    out = vault.redact(out);
  }

  // 2. Enforce prefix-based masking for any remaining raw secrets (ignoring already-masked strings containing *)
  for (const pat of RAW_SECRET_PREFIX_PATTERNS) {
    pat.lastIndex = 0;
    out = out.replace(pat, (match) => {
      if (match.includes('*') || match.includes('[REDACTED')) return match;
      return maskLiteral(match);
    });
  }

  if (out.length > maxChars) {
    out = `${out.slice(0, Math.max(0, maxChars - 1)).trimEnd()}…`;
  }
  return out;
}

function deriveEntityType(
  out: HandlerOutput,
  outcomeKind: TurnOutcomeKind,
): ConversationTurnMeta['entityType'] {
  if (outcomeKind === 'out_of_scope') return 'none';
  if (out.referencedDomains.length > 0 && out.referencedFindings.length === 0) return 'domain';
  if (out.referencedFiles.length > 0 && out.referencedFindings.length === 0) return 'file';
  if (out.referencedFindings.length > 0) return 'finding';
  if (outcomeKind === 'fix' || outcomeKind === 'diff' || outcomeKind === 'approve') return 'patch';
  return 'audit';
}

function buildLocalHint(audit: DeterministicAuditPayload, out: HandlerOutput): string | null {
  if (!out.needsLocalDiffHint && !out.needsTruncatedTestHint) return null;
  const firstFinding = out.referencedFindings[0] ?? sortFindingsByPriority(audit.findings ?? [])[0];
  const loc = firstFinding
    ? `${firstFinding.file}${firstFinding.line > 0 ? `:${firstFinding.line}` : ''}`
    : null;
  if (out.needsTruncatedTestHint) {
    return `Hint: Run your test suite locally${loc ? ` and inspect \`${loc}\`` : ''} for the full untruncated stack trace.`;
  }
  return `Hint: Run \`git diff\`${loc ? ` or inspect \`${loc}\`` : ''} locally to verify exact line changes.`;
}

/**
 * Strict 5-Stage Deterministic Q&A Pipeline + Mandatory Zero-Leak Post-Pass.
 * Pure, zero-dependency, synchronous, deterministic (< 15ms).
 */
export function answerDeterministicQa(
  rawAudit: DeterministicAuditPayload,
  question: string,
  history: readonly ConversationTurn[] = [],
): DeterministicQaResponse {
  const start = performance.now();

  // Normalize missing optional fields gracefully so partial payloads never throw
  const audit: DeterministicAuditPayload = {
    repo: rawAudit.repo || 'unknown/repo',
    prNumber: rawAudit.prNumber ?? 0,
    prTitle: rawAudit.prTitle ?? null,
    commitSha: rawAudit.commitSha || '',
    branch: rawAudit.branch ?? null,
    riskScore: rawAudit.riskScore ?? 0,
    severity: rawAudit.severity || 'Low',
    status: rawAudit.status || 'unknown',
    riskContributions: rawAudit.riskContributions ?? null,
    findings: Array.isArray(rawAudit.findings) ? rawAudit.findings : [],
    egressEvents: Array.isArray(rawAudit.egressEvents) ? rawAudit.egressEvents : [],
    canaryHits: Array.isArray(rawAudit.canaryHits) ? rawAudit.canaryHits : [],
    patch: rawAudit.patch ?? null,
    sprite: rawAudit.sprite ?? null,
    relatedIncidents: Array.isArray(rawAudit.relatedIncidents) ? rawAudit.relatedIncidents : [],
  };

  const suggestedQuestions = buildSuggestedQuestions(audit);

  const finalize = (
    out: HandlerOutput,
    outcomeKind: TurnOutcomeKind,
    winningIntents: IntentId[],
    isOutOfScope: boolean,
  ): DeterministicQaResponse => {
    const hint = buildLocalHint(audit, out);
    const combined = hint ? `${out.text}\n\n${hint}` : out.text;
    const sanitized = sanitizeZeroLeakOutput(combined);

    const meta: ConversationTurnMeta = {
      entityType: deriveEntityType(out, outcomeKind),
      findingIds: [...new Set(out.referencedFindings.map((f) => f.id))],
      files: [...new Set(out.referencedFiles.filter(Boolean))],
      domains: [...new Set(out.referencedDomains.map((d) => d.toLowerCase()).filter(Boolean))],
      lastIntent: outcomeKind,
      suggestedQuestions,
      badge: DETERMINISTIC_BADGE,
    };

    return {
      answer: sanitized,
      badge: DETERMINISTIC_BADGE,
      meta,
      isOutOfScope,
      winningIntents,
      latencyMs: Math.round((performance.now() - start) * 100) / 100,
    };
  };

  // Stage 1: Pre-process & normalize
  const nq = normalizeQuery(question);
  if (!nq.cleaned || nq.isPromptInjection) {
    return finalize(handleOutOfScope(audit), 'out_of_scope', [], true);
  }

  // Stage 2 & 3: Entity-first lookup + single-turn conversational thread memory resolution
  const explicitEntities = resolveEntities(nq, audit);
  const entities = resolveConversationalContext(nq, audit, history, explicitEntities);

  // Stage 4: Weighted multi-intent confidence scoring & concept clustering
  const ranked = scoreIntents(nq, entities);
  const winners = selectWinningIntents(ranked, nq);

  // Clean / zero-finding audit short-circuit (after verifying question is on-topic & not metadata/draft)
  const isCleanAudit =
    audit.findings.length === 0 &&
    audit.egressEvents.filter((e) => e.flagged).length === 0 &&
    (audit.canaryHits ?? []).length === 0;

  if (isCleanAudit) {
    if (winners.length === 0 && !nq.isShortVague) {
      return finalize(handleOutOfScope(audit), 'out_of_scope', [], true);
    }
    const primary = winners[0];
    if (primary === 'metadata' || primary === 'draft' || primary === 'egress') {
      if (primary === 'egress' && entities.absentDomains.length > 0) {
        return finalize(dispatchIntent('egress', nq, audit, entities), 'egress', ['egress'], false);
      }
      if (primary === 'metadata' || primary === 'draft') {
        return finalize(dispatchIntent(primary, nq, audit, entities), primary, [primary], false);
      }
    }
    return finalize(handleCleanShortCircuit(audit), 'clean_short_circuit', winners, false);
  }

  // Stage 5: Low confidence -> Smart disambiguation or Grounded Out-of-Scope
  if (winners.length === 0) {
    if (nq.isShortVague) {
      return finalize(handleDisambiguation(audit), 'disambiguation', [], false);
    }
    return finalize(handleOutOfScope(audit), 'out_of_scope', [], true);
  }

  // Single winning intent
  if (winners.length === 1) {
    const intent = winners[0]!;
    const out = dispatchIntent(intent, nq, audit, entities);
    return finalize(out, intent, [intent], false);
  }

  // Compound query: render 2-3 clearly labeled sub-sections in one cohesive response
  const sections: string[] = [];
  const allFindings: DeterministicFinding[] = [];
  const allFiles: string[] = [];
  const allDomains: string[] = [];
  let needsLocalDiffHint = false;
  let needsTruncatedTestHint = false;

  for (const intent of winners) {
    const sub = dispatchIntent(intent, nq, audit, entities);
    sections.push(`**${INTENT_SECTION_TITLE[intent]}**\n${sub.text}`);
    allFindings.push(...sub.referencedFindings);
    allFiles.push(...sub.referencedFiles);
    allDomains.push(...sub.referencedDomains);
    if (sub.needsLocalDiffHint) needsLocalDiffHint = true;
    if (sub.needsTruncatedTestHint) needsTruncatedTestHint = true;
  }

  const compoundLead = `Here are the exact answers for your **${winners.length}** questions on PR #${audit.prNumber}:`;
  return finalize(
    {
      text: `${compoundLead}\n\n${sections.join('\n\n')}`,
      referencedFindings: allFindings,
      referencedFiles: allFiles,
      referencedDomains: allDomains,
      needsLocalDiffHint,
      needsTruncatedTestHint,
    },
    'compound',
    winners,
    false,
  );
}

/**
 * Adapts SpriteGuard's persisted ScanRecord + ScanReport + PatchRecord into
 * the normalized DeterministicAuditPayload used by the deterministic Q&A engine.
 */
export function adaptScanToAuditPayload(input: {
  scan: ScanRecord;
  report?: ScanReport | null;
  patch?: PatchRecord | null;
  relatedIncidents?: PastIncident[];
}): DeterministicAuditPayload {
  const { scan, patch } = input;
  const report = input.report ?? scan.report ?? null;
  const staticLeaks = report?.staticLeaks ?? [];
  const rawFindings = report?.audit.findings ?? [];

  const findings: DeterministicFinding[] = rawFindings.map((f) => {
    const matchedLeak = staticLeaks.find(
      (l) => l.file === f.file && (l.line === f.line || !f.line),
    );
    return {
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category === 'secret_leak' ? 'secret' : f.category === 'malicious_egress' ? 'egress' : f.category,
      file: f.file,
      line: f.line,
      redactedSecret: matchedLeak?.redacted ?? null,
      entropy: matchedLeak?.entropy ?? null,
      fingerprint: matchedLeak?.fingerprint ?? null,
      evidence: f.evidence,
      exploitability: f.exploitability,
      runtimeProof: f.runtimeProof,
      remediation: f.remediation,
      confidence: f.confidence,
      source: f.source,
      commitSha: matchedLeak?.commitSha ?? null,
      isHistoryLeak: matchedLeak?.source === 'commit',
    };
  });

  // Ensure any staticLeak that wasn't turned into a Finding still appears
  for (const leak of staticLeaks) {
    const already = findings.some(
      (f) => f.fingerprint === leak.fingerprint || (f.file === leak.file && f.line === leak.line),
    );
    if (!already) {
      findings.push({
        id: `leak-${leak.fingerprint}`,
        title: leak.ruleName,
        severity: leak.severity,
        category: 'secret',
        file: leak.file,
        line: leak.line,
        redactedSecret: leak.redacted,
        entropy: leak.entropy,
        fingerprint: leak.fingerprint,
        evidence: leak.context,
        source: 'static',
        commitSha: leak.commitSha ?? null,
        isHistoryLeak: leak.source === 'commit',
      });
    }
  }

  const rawDomains = report?.egress.domains ?? scan.egressDomains ?? [];
  const egressEvents: DeterministicEgressEvent[] = rawDomains.map((d) => {
    const assoc = findings.find(
      (f) =>
        f.category === 'egress' &&
        `${f.title} ${f.evidence ?? ''} ${f.runtimeProof ?? ''}`.toLowerCase().includes(d.host.toLowerCase()),
    );
    return {
      domain: d.host,
      port: d.ports[0] ?? null,
      phase: d.phases[0] ?? 'runtime',
      hitCount: d.hits,
      sampleUrls: d.sampleUrls,
      flagged: d.flagged,
      reasons: d.reasons,
      associatedFindingId: assoc?.id ?? null,
    };
  });

  const canaryHits = (report?.egress.canaryExfiltrations ?? []).map((c) => ({
    canary: c.canary,
    channel: c.channel,
    detail: c.detail,
  }));

  // Extract any captured test command output from report.egress.commands
  const testCmd = (report?.egress.commands ?? []).find(
    (c) => /test/i.test(c.label) || /test/i.test(c.command),
  );
  const testOutput = testCmd
    ? [
        testCmd.exitCode !== null ? `Command exited with code ${testCmd.exitCode}` : '',
        testCmd.stdoutTail,
        testCmd.stderrTail,
      ]
        .filter(Boolean)
        .join('\n')
    : null;

  const v = patch?.verification ?? null;
  const validationStatus = !v
    ? null
    : v.status === 'verified'
      ? 'passed'
      : v.status === 'verified_with_warnings'
        ? 'passed_with_warnings'
        : 'failed';
  const testStatus = !v
    ? null
    : !v.testsAfter.ran
      ? 'skipped'
      : v.testsAfter.passed
        ? 'passed'
        : 'failed';

  const durationMs = report?.timings
    ? Object.values(report.timings).reduce((acc, n) => acc + (Number.isFinite(n) ? n : 0), 0)
    : null;

  return {
    repo: scan.repoFullName,
    prNumber: scan.prNumber,
    prTitle: scan.prTitle,
    commitSha: scan.headSha,
    branch: scan.headRef,
    riskScore: scan.riskScore ?? 0,
    severity: scan.severity ?? 'Low',
    status: scan.status,
    findings,
    egressEvents,
    canaryHits,
    patch: patch
      ? {
          status: patch.status,
          summary: patch.summary,
          diff: patch.diff,
          validationStatus,
          testStatus,
          testSummary: v?.testsAfter.summary ?? null,
          testOutput: testStatus === 'failed' ? testOutput : null,
          resolvedLeaks: v?.resolvedFingerprints.length ?? 0,
          remainingLeaks: v?.remainingLeaks.length ?? 0,
          flaggedEgressAfterPatch: v?.flaggedEgressAfter.length ?? 0,
          pushed: patch.status === 'pushed',
          commitSha: patch.commitSha,
          generator: patch.generator,
          postMergeActions: patch.postMergeActions,
          notes: v?.notes ?? [],
        }
      : null,
    sprite: {
      id: scan.spriteName ?? report?.sandbox.spriteName ?? null,
      lifecycle: scan.spriteState,
      checkpoint: scan.checkpointId,
      durationMs,
      runtimeEnv: report?.egress.projectType ?? null,
      isolationSandbox: report?.sandbox.driver ?? null,
    },
    relatedIncidents: (input.relatedIncidents ?? report?.pastIncidents ?? []).map((p) => ({
      prNumber: p.prNumber,
      title: p.title,
      similarity: p.similarity,
    })),
  };
}
