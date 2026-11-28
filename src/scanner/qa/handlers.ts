import { isEgressFinding, isSecretFinding, sortFindingsByPriority } from './entities.js';
import {
  extractFileDiffHunks,
  parseTestFailure,
  renderEvidenceBlock,
  summarizePatchDiff,
} from './logParser.js';
import {
  draftEscalationComment,
  explainThreatImpact,
  synthesizeRemediationSnippet,
} from './remediation.js';
import type {
  DeterministicAuditPayload,
  DeterministicEgressEvent,
  DeterministicFinding,
  EntityResolution,
  IntentId,
  NormalizedQuery,
} from './types.js';

/**
 * Deterministic intent handlers, quantitative/boolean engine, disambiguation,
 * clean audit short-circuit, out-of-scope responder, and dynamic follow-up generator.
 */

export const OFF_TOPIC_PREFIX =
  'I only answer security and code questions grounded in this Pull Request audit.';

export interface HandlerOutput {
  text: string;
  referencedFindings: DeterministicFinding[];
  referencedFiles: string[];
  referencedDomains: string[];
  needsLocalDiffHint?: boolean;
  needsTruncatedTestHint?: boolean;
}

function locOf(f: DeterministicFinding): string {
  return f.line > 0 ? `${f.file}:${f.line}` : f.file;
}

function hostPortOf(ev: DeterministicEgressEvent): string {
  return ev.port ? `${ev.domain}:${ev.port}` : ev.domain;
}

function isPatchValidationPassing(status?: string | null): boolean {
  const s = (status ?? '').toLowerCase();
  return s === 'passed' || s === 'verified' || s === 'passed_with_warnings' || s === 'verified_with_warnings';
}

function isPatchValidationClean(status?: string | null): boolean {
  const s = (status ?? '').toLowerCase();
  return s === 'passed' || s === 'verified';
}

function formatStageLabel(val?: string | null, fallback = 'pending'): string {
  return val && val.trim() ? val.trim() : fallback;
}

function computeRiskBreakdown(audit: DeterministicAuditPayload): Array<{ label: string; points: number }> {
  if (audit.riskContributions?.breakdown && audit.riskContributions.breakdown.length > 0) {
    return audit.riskContributions.breakdown;
  }
  const out: Array<{ label: string; points: number }> = [];
  if (audit.riskContributions?.secrets) out.push({ label: 'Secrets & Credentials', points: audit.riskContributions.secrets });
  if (audit.riskContributions?.egress) out.push({ label: 'Runtime & Egress', points: audit.riskContributions.egress });
  if (audit.riskContributions?.code) out.push({ label: 'Code & Injection', points: audit.riskContributions.code });
  if (out.length > 0) return out;

  // Deterministic computation from findings if riskContributions was not supplied
  let secPts = 0;
  let egPts = 0;
  let codePts = 0;
  const sevWeight: Record<string, number> = { critical: 34, high: 22, medium: 11, low: 4, info: 0 };
  for (const f of audit.findings ?? []) {
    const pts = f.riskContribution ?? sevWeight[f.severity] ?? 10;
    if (isSecretFinding(f)) secPts += pts;
    else if (isEgressFinding(f)) egPts += pts;
    else codePts += pts;
  }
  if (secPts > 0) out.push({ label: 'Secrets & Credentials', points: secPts });
  if (egPts > 0) out.push({ label: 'Runtime & Egress', points: egPts });
  if (codePts > 0) out.push({ label: 'Code & Injection', points: codePts });
  return out;
}

export function buildSuggestedQuestions(audit: DeterministicAuditPayload): string[] {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const suggestions: string[] = [];

  if (sorted.length === 0 && flaggedEgress.length === 0) {
    return [
      `Is PR #${audit.prNumber} safe to merge?`,
      'Show sandbox execution metadata',
      'Draft a summary comment for my team',
    ];
  }

  const secretFinding = sorted.find(isSecretFinding);
  if (secretFinding) {
    suggestions.push(`Where was ${secretFinding.title} found?`);
  }
  if (audit.patch?.testStatus === 'failed') {
    suggestions.push('Why did the patch tests fail?');
  } else if (audit.patch) {
    suggestions.push('Can I merge or run /spriteguard approve?');
  }
  const topEgress = flaggedEgress[0];
  if (topEgress) {
    suggestions.push(`What is ${topEgress.domain} doing?`);
  }
  const targetFile = sorted.find((f) => f.file && f !== secretFinding)?.file ?? sorted[0]?.file;
  if (targetFile) {
    suggestions.push(`How do I fix ${targetFile}?`);
  }
  if (suggestions.length < 3) {
    suggestions.push('What are my next steps?');
  }
  if (suggestions.length < 3) {
    suggestions.push('Is this exploitable?');
  }
  return [...new Set(suggestions)].slice(0, 4);
}

export function handleCleanShortCircuit(audit: DeterministicAuditPayload): HandlerOutput {
  const sha7 = (audit.commitSha || '').slice(0, 7) || 'unknown';
  return {
    text: [
      `Yes — PR #${audit.prNumber} (\`${audit.repo}\`, commit \`${sha7}\`) passed all security checks with **riskScore: 0/100** (Clean).`,
      '',
      '- **Exploitability:** No exploitable vulnerabilities, exposed credentials, or unauthorized outbound egress were detected.',
      '- **Credentials:** Zero leaked secrets found; no key rotation is required.',
      '- **Merge & Remediation:** No remediation patch or `/spriteguard approve` command is required.',
    ].join('\n'),
    referencedFindings: [],
    referencedFiles: [],
    referencedDomains: [],
  };
}

export function handleSecrets(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const allSecrets = sortFindingsByPriority(audit.findings ?? []).filter(isSecretFinding);
  const scoped = entities.matchedFindings.length > 0
    ? entities.matchedFindings.filter(isSecretFinding)
    : allSecrets;
  const targets = scoped.length > 0 ? scoped : allSecrets;

  if (targets.length === 0) {
    return {
      text: `No exposed secrets or credentials were detected in PR #${audit.prNumber}.`,
      referencedFindings: [],
      referencedFiles: [],
      referencedDomains: [],
    };
  }

  const lines: string[] = [
    targets.length === 1
      ? `**1** exposed secret was detected in PR #${audit.prNumber} at \`${locOf(targets[0]!)}\`.`
      : `**${targets.length}** exposed secrets were detected in PR #${audit.prNumber}.`,
    '',
  ];

  for (const f of targets) {
    const metaParts: string[] = [];
    if (f.redactedSecret) metaParts.push(`preview \`${f.redactedSecret}\``);
    if (f.entropy !== null && f.entropy !== undefined) metaParts.push(`entropy \`${f.entropy}\``);
    if (f.fingerprint) metaParts.push(`fingerprint \`${f.fingerprint}\``);
    lines.push(
      `- **[${f.severity.toUpperCase()}] ${f.title}** at \`${locOf(f)}\`${metaParts.length > 0 ? ` — ${metaParts.join(', ')}` : ''}`,
    );
  }

  lines.push(
    '- **Action Required — Revoke & Rotate:** Revoke and rotate every exposed credential at the provider immediately, and squash/rewrite PR commits so leaked values do not remain in git history (code patches never invalidate already-leaked keys).',
  );

  return {
    text: lines.join('\n'),
    referencedFindings: targets,
    referencedFiles: [...new Set(targets.map((f) => f.file).filter(Boolean))],
    referencedDomains: [],
  };
}

export function handleLocation(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const targets = entities.matchedFindings.length > 0 ? entities.matchedFindings : sorted;
  const targetFiles =
    entities.matchedFiles.length > 0
      ? entities.matchedFiles
      : [...new Set(targets.map((f) => f.file).filter(Boolean))];

  if (targets.length === 0 && targetFiles.length === 0) {
    return {
      text: `No flagged files or lines were recorded in PR #${audit.prNumber}.`,
      referencedFindings: [],
      referencedFiles: [],
      referencedDomains: [],
    };
  }

  const lines: string[] = [
    entities.matchedFiles.length === 1
      ? `Flagged details for \`${entities.matchedFiles[0]}\` (${targets.length} finding${targets.length === 1 ? '' : 's'}):`
      : `SpriteGuard flagged **${targets.length}** location${targets.length === 1 ? '' : 's'} across **${targetFiles.length}** file${targetFiles.length === 1 ? '' : 's'} in PR #${audit.prNumber}:`,
    '',
  ];

  for (const f of targets) {
    const detail = f.redactedSecret
      ? `${f.title} (\`${f.redactedSecret}\`)`
      : f.title;
    lines.push(`- \`${locOf(f)}\` — **[${f.severity.toUpperCase()}]** ${detail}`);
  }

  // If user asked directly about a specific file (e.g. "tell me about payment.js" or "paymnet.js"),
  // also include its code evidence and proposed diff hunk for immediate precision!
  let needsLocalDiffHint = false;
  if (entities.matchedFiles.length > 0) {
    for (const f of targets.slice(0, 2)) {
      if (f.evidence && f.evidence.trim()) {
        lines.push('', renderEvidenceBlock(f));
      }
    }
    const hunks = extractFileDiffHunks(audit.patch?.diff, entities.matchedFiles);
    if (hunks.length > 0) {
      lines.push('', `Proposed patch diff for \`${entities.matchedFiles.join('`, `')}\`:`, '```diff', hunks.map((hk) => hk.rawHunk).join('\n\n'), '```');
    } else if (audit.patch && !audit.patch.diff) {
      needsLocalDiffHint = true;
    }
  }

  return {
    text: lines.join('\n'),
    referencedFindings: targets,
    referencedFiles: targetFiles,
    referencedDomains: [],
    needsLocalDiffHint,
  };
}

export function handleEgress(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const allEgress = audit.egressEvents ?? [];
  const flagged = allEgress.filter((e) => e.flagged);
  const canaryHits = audit.canaryHits ?? [];

  // Explicit absent-domain handling (e.g., "any egress to google.com?")
  if (entities.absentDomains.length > 0 && entities.matchedDomains.length === 0) {
    const queried = entities.absentDomains.map((d) => `\`${d}\``).join(', ');
    const actualList =
      flagged.length > 0
        ? ` Flagged egress was only observed to ${flagged.map((e) => `\`${hostPortOf(e)}\``).join(', ')}.`
        : ' No unauthorized outbound domains were contacted in this PR.';
    return {
      text: `No — no outbound network egress to ${queried} was recorded in PR #${audit.prNumber}.${actualList}`,
      referencedFindings: [],
      referencedFiles: [],
      referencedDomains: flagged.map((e) => e.domain),
    };
  }

  const targets = entities.matchedDomains.length > 0 ? entities.matchedDomains : flagged.length > 0 ? flagged : allEgress;
  const associatedFindings = sortFindingsByPriority(audit.findings ?? []).filter(
    (f) => isEgressFinding(f) || targets.some((ev) => ev.associatedFindingId === f.id),
  );

  if (targets.length === 0 && canaryHits.length === 0) {
    return {
      text: `No outbound network egress or canary exfiltration was recorded in PR #${audit.prNumber}.`,
      referencedFindings: [],
      referencedFiles: [],
      referencedDomains: [],
    };
  }

  const lines: string[] = [
    entities.matchedDomains.length === 1
      ? `Outbound traffic to \`${hostPortOf(entities.matchedDomains[0]!)}\` was observed **${entities.matchedDomains[0]!.hitCount}** time(s) during the \`${entities.matchedDomains[0]!.phase}\` phase (${entities.matchedDomains[0]!.flagged ? 'FLAGGED' : 'allowlisted'}).`
      : flagged.length > 0
        ? `PR #${audit.prNumber} triggered **${flagged.length}** flagged outbound egress destination${flagged.length === 1 ? '' : 's'} (out of ${allEgress.length} contacted).`
        : `All **${allEgress.length}** outbound domain${allEgress.length === 1 ? '' : 's'} contacted in PR #${audit.prNumber} are allowlisted.`,
    '',
  ];

  for (const ev of targets) {
    const urls = ev.sampleUrls && ev.sampleUrls.length > 0 ? ` · sample: \`${ev.sampleUrls[0]}\`` : '';
    const reasons = ev.reasons && ev.reasons.length > 0 ? ` (${ev.reasons.join('; ')})` : '';
    lines.push(
      `- \`${hostPortOf(ev)}\` — **${ev.flagged ? 'FLAGGED' : 'Allowlisted'}**${reasons} · phase: \`${ev.phase}\` · **${ev.hitCount}** hit(s)${urls}`,
    );
  }

  if (associatedFindings.length > 0) {
    for (const f of associatedFindings.slice(0, 3)) {
      lines.push(`- **Associated Finding:** [${f.severity.toUpperCase()}] ${f.title} at \`${locOf(f)}\``);
    }
  }

  if (canaryHits.length > 0) {
    lines.push(
      `- **Canary Traps Triggered (${canaryHits.length}):** ${canaryHits
        .map((c) => `\`${c.canary}\` via ${c.channel} (${c.detail})`)
        .join('; ')}`,
    );
  }

  return {
    text: lines.join('\n'),
    referencedFindings: associatedFindings,
    referencedFiles: [...new Set(associatedFindings.map((f) => f.file).filter(Boolean))],
    referencedDomains: targets.map((e) => e.domain),
  };
}

export function handleFix(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const scopedFindings = entities.matchedFindings.length > 0 ? entities.matchedFindings : sorted;
  const scopedFiles =
    entities.matchedFiles.length > 0
      ? entities.matchedFiles
      : [...new Set(scopedFindings.map((f) => f.file).filter(Boolean))];
  const patch = audit.patch;
  const hasSecrets = scopedFindings.some(isSecretFinding) || sorted.some(isSecretFinding);
  const parsedFailure = parseTestFailure(patch?.testOutput);

  const lines: string[] = [];
  let needsLocalDiffHint = false;
  let needsTruncatedTestHint = false;

  if (entities.requestedFailingTest && patch?.testStatus === 'failed') {
    lines.push(
      `Patch verification tests **failed** for PR #${audit.prNumber}${parsedFailure?.exitCode !== null && parsedFailure?.exitCode !== undefined ? ` (exit code \`${parsedFailure.exitCode}\`)` : ''}.`,
    );
  } else if (entities.isEntityScoped && scopedFindings.length > 0) {
    const f0 = scopedFindings[0]!;
    lines.push(
      `Here is the remediation and verification status for **${f0.title}** at \`${locOf(f0)}\`:`,
    );
  } else if (!patch) {
    lines.push(
      scopedFindings.length === 0
        ? `No remediation patch is required for PR #${audit.prNumber}.`
        : `No automated patch is available for PR #${audit.prNumber}; apply the synthesized fix below locally.`,
    );
  } else if (patch.testStatus === 'failed') {
    lines.push(
      `A remediation patch was drafted for PR #${audit.prNumber}, but **verification tests failed**${parsedFailure?.exitCode !== null && parsedFailure?.exitCode !== undefined ? ` (exit code \`${parsedFailure.exitCode}\`)` : ''}.`,
    );
  } else {
    lines.push(
      `A remediation patch for PR #${audit.prNumber} is \`${patch.status}\` and ${patch.testStatus === 'passed' ? 'passed verification tests' : `has test status \`${formatStageLabel(patch.testStatus, 'not run')}\``}.`,
    );
  }

  lines.push('');

  // 1. Patch pipeline stages
  if (patch) {
    const genStage = `Generated (\`${formatStageLabel(patch.generator, 'heuristic')}\`)`;
    const valStage = `Validated (\`${formatStageLabel(patch.validationStatus, 'pending')}\`)`;
    const testStage = `Tested (\`${formatStageLabel(patch.testStatus, 'not_run')}\`${patch.testSummary ? ` — ${patch.testSummary}` : ''})`;
    const approvalStage = patch.pushed
      ? 'Approval (approved)'
      : isPatchValidationPassing(patch.validationStatus) && patch.testStatus === 'passed'
        ? 'Approval (ready for `/spriteguard approve`)'
        : 'Approval (blocked)';
    const pushedStage = patch.pushed
      ? `Pushed (\`${(patch.commitSha ?? '').slice(0, 7) || 'committed'}\`)`
      : 'Pushed (not pushed)';

    lines.push(`- **Patch Pipeline:** ${genStage} -> ${valStage} -> ${testStage} -> ${approvalStage} -> ${pushedStage}`);

    if (patch.testStatus === 'passed') {
      lines.push(
        `- **Test & Re-Scan Verification:** Tests passed${patch.testSummary ? ` (${patch.testSummary})` : ''}; resolved ${patch.resolvedLeaks ?? 0} leak(s), ${patch.remainingLeaks ?? 0} remaining head leak(s), ${patch.flaggedEgressAfterPatch ?? 0} flagged egress after patch.`,
      );
    } else if (patch.testStatus === 'failed') {
      if (parsedFailure) {
        if (parsedFailure.exitCode !== null) lines.push(`- **Exit Code:** \`${parsedFailure.exitCode}\``);
        if (parsedFailure.failingSuite) lines.push(`- **Failing Suite / Case:** \`${parsedFailure.failingSuite}\``);
        if (parsedFailure.primaryError) lines.push(`- **Primary Error:** \`${parsedFailure.primaryError}\``);
        if (parsedFailure.truncated) needsTruncatedTestHint = true;
      } else {
        lines.push('- **Test Output:** Not available for this audit run.');
        needsTruncatedTestHint = true;
      }
    }

    // 2. Diff Summary Synthesizer
    const diffSummaries = summarizePatchDiff(patch.diff, entities.matchedFiles.length > 0 ? entities.matchedFiles : undefined);
    if (diffSummaries.length > 0) {
      lines.push('- **Drafted Patch Changes:**');
      for (const ds of diffSummaries) {
        lines.push(`  - ${ds.description}`);
      }
    } else if (patch.summary) {
      lines.push(`- **Patch Summary:** ${patch.summary}`);
      if (!patch.diff) needsLocalDiffHint = true;
    } else if (!patch.diff) {
      needsLocalDiffHint = true;
    }
  } else {
    needsLocalDiffHint = scopedFindings.length > 0;
  }

  // 3. Language-aware synthesized remediation snippet (always provide when patch is null, failed, or entity-scoped)
  const shouldSynthesize =
    scopedFindings.length > 0 && (!patch || !patch.diff || patch.testStatus === 'failed' || entities.isEntityScoped);
  if (shouldSynthesize) {
    const snippets = scopedFindings.slice(0, 2).map((f) => synthesizeRemediationSnippet(f, audit.egressEvents ?? []));
    lines.push('', ...snippets);
  }

  if (hasSecrets) {
    lines.push(
      '',
      '- **Commit History & Rotation:** Squash PR commits (or rewrite branch history) so leaked credentials are purged from git history, and revoke/rotate all exposed keys at the provider.',
    );
  }

  return {
    text: lines.join('\n'),
    referencedFindings: scopedFindings,
    referencedFiles: scopedFiles,
    referencedDomains: [],
    needsLocalDiffHint,
    needsTruncatedTestHint,
  };
}

export function handleExploit(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const targets = entities.matchedFindings.length > 0 ? entities.matchedFindings : sorted;
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const canaryHits = audit.canaryHits ?? [];
  const hasSecrets = targets.some(isSecretFinding);

  if (targets.length === 0 && flaggedEgress.length === 0 && canaryHits.length === 0) {
    return handleCleanShortCircuit(audit);
  }

  const highRisk =
    audit.riskScore >= 50 ||
    hasSecrets ||
    canaryHits.length > 0 ||
    targets.some((f) => f.severity === 'critical' || f.severity === 'high');

  const breakdown = computeRiskBreakdown(audit);
  const breakdownText =
    breakdown.length > 0
      ? breakdown.map((b) => `\`+${b.points}\` ${b.label}`).join(', ')
      : `total \`${audit.riskScore}/100\``;

  const lines: string[] = [
    highRisk
      ? `Yes — PR #${audit.prNumber} is directly exploitable with a **${audit.riskScore}/100** (${audit.severity}) risk score (${breakdownText}).`
      : `PR #${audit.prNumber} carries a **${audit.riskScore}/100** (${audit.severity}) risk score (${breakdownText}) and should be reviewed before merging.`,
    '',
  ];

  for (const f of targets.slice(0, 6)) {
    lines.push(`- ${explainThreatImpact(f, audit.egressEvents ?? [])}`);
  }

  if (canaryHits.length > 0) {
    lines.push(
      `- **Active Runtime Proof:** ${canaryHits.length} canary trap(s) exfiltrated during sandbox execution (${canaryHits
        .map((c) => `\`${c.canary}\` via ${c.channel}`)
        .join(', ')}).`,
    );
  }

  if (hasSecrets) {
    lines.push(
      '- **Rotate Exposed Credentials:** Revoke and rotate every exposed key at the provider immediately — code fixes do not invalidate leaked credentials.',
    );
  }

  return {
    text: lines.join('\n'),
    referencedFindings: targets,
    referencedFiles: [...new Set(targets.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleApprove(audit: DeterministicAuditPayload): HandlerOutput {
  const patch = audit.patch;
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const hasSecrets = sorted.some(isSecretFinding);

  if (sorted.length === 0 && flaggedEgress.length === 0) {
    return handleCleanShortCircuit(audit);
  }

  if (patch?.pushed) {
    return {
      text: [
        `Yes — the verified patch for PR #${audit.prNumber} has already been pushed${patch.commitSha ? ` (\`${patch.commitSha.slice(0, 7)}\`)` : ''}.`,
        '',
        hasSecrets
          ? '- **Remaining Action:** Confirm all exposed credentials have been revoked/rotated at the provider before merging.'
          : '- **Status:** The isolated Sprite was cleaned up after commit; proceed with normal maintainer merge checks.',
      ].join('\n'),
      referencedFindings: sorted,
      referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
      referencedDomains: [],
    };
  }

  const valPassed = isPatchValidationPassing(patch?.validationStatus);
  const valClean = isPatchValidationClean(patch?.validationStatus);
  const testPassed = patch?.testStatus === 'passed';
  const eligible = Boolean(patch && valPassed && testPassed);

  if (!eligible) {
    const reasons: string[] = [];
    if (!patch) reasons.push('no automated patch was generated');
    else {
      if (!valPassed) reasons.push(`patch validation status is \`${formatStageLabel(patch.validationStatus, 'pending')}\``);
      if (!testPassed) reasons.push(`patch test status is \`${formatStageLabel(patch.testStatus, 'not_run')}\``);
    }
    const parsedFailure = parseTestFailure(patch?.testOutput);
    const lines: string[] = [
      `No — PR #${audit.prNumber} is **not eligible** for \`/spriteguard approve\` yet because ${reasons.join(' and ')}.`,
      '',
      '- **Eligibility Gate:** `/spriteguard approve` requires both `validationStatus === "passed"` and `testStatus === "passed"` before committing.',
    ];
    if (parsedFailure?.primaryError) {
      lines.push(`- **Blocking Test Error:** \`${parsedFailure.primaryError}\``);
    }
    lines.push(
      '- **How to Unblock:** Fix the failing check locally, push a new commit to re-run SpriteGuard, and rotate any exposed secrets.',
    );
    return {
      text: lines.join('\n'),
      referencedFindings: sorted,
      referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
      referencedDomains: flaggedEgress.map((e) => e.domain),
    };
  }

  const lines: string[] = [
    valClean
      ? `Yes — PR #${audit.prNumber} is eligible for \`/spriteguard approve\` (validation and tests both passed).`
      : `Yes (with warnings) — PR #${audit.prNumber} passed tests and can be committed with \`/spriteguard approve\`, though warnings remain (\`${patch?.validationStatus}\`).`,
    '',
    '- **What Approval Does:** A maintainer commenting `/spriteguard approve` wakes the sleeping Sprite, cross-verifies the patch `diffSha256`, commits strictly through the separated **GitHub Write Connector**, and destroys/cleans up the Sprite.',
  ];
  if (hasSecrets) {
    lines.push(
      '- **Credential Rotation Still Required:** Merging the code fix does not invalidate already-leaked keys — revoke and rotate them at the provider and squash leaked PR commits.',
    );
  }
  return {
    text: lines.join('\n'),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleDiff(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const diff = audit.patch?.diff;
  if (!diff || !diff.trim()) {
    return {
      text: `Patch diff for PR #${audit.prNumber}: Not available for this audit run.`,
      referencedFindings: entities.matchedFindings,
      referencedFiles: entities.matchedFiles,
      referencedDomains: [],
      needsLocalDiffHint: true,
    };
  }

  const targetFiles =
    entities.matchedFiles.length > 0
      ? entities.matchedFiles
      : entities.matchedFindings.length > 0
        ? [...new Set(entities.matchedFindings.map((f) => f.file).filter(Boolean))]
        : undefined;

  const hunks = extractFileDiffHunks(diff, targetFiles);
  if (hunks.length === 0) {
    return {
      text: `No patch diff hunks were found for ${targetFiles ? `\`${targetFiles.join('`, `')}\`` : `PR #${audit.prNumber}`}.`,
      referencedFindings: entities.matchedFindings,
      referencedFiles: targetFiles ?? [],
      referencedDomains: [],
      needsLocalDiffHint: true,
    };
  }

  const lines: string[] = [
    hunks.length === 1
      ? `Here is the proposed patch diff for \`${hunks[0]!.file}\`:`
      : `Here are the proposed patch diffs across **${hunks.length}** files in PR #${audit.prNumber}:`,
    '',
  ];
  for (const hk of hunks) {
    lines.push(`- ${hk.description}`);
  }
  lines.push('', '```diff', hunks.map((hk) => hk.rawHunk).join('\n\n').slice(0, 3200), '```');

  return {
    text: lines.join('\n'),
    referencedFindings: entities.matchedFindings,
    referencedFiles: hunks.map((h) => h.file),
    referencedDomains: [],
  };
}

export function handleEvidence(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const targets = entities.matchedFindings.length > 0 ? entities.matchedFindings : sorted.slice(0, 3);

  if (targets.length === 0) {
    return {
      text: `Code evidence for PR #${audit.prNumber}: Not available for this audit run.`,
      referencedFindings: [],
      referencedFiles: [],
      referencedDomains: [],
    };
  }

  const lines: string[] = [
    targets.length === 1
      ? `Here is the offending code captured at \`${locOf(targets[0]!)}\` (**${targets[0]!.title}**):`
      : `Here is the offending code evidence for **${targets.length}** finding(s) in PR #${audit.prNumber}:`,
    '',
  ];

  for (const f of targets.slice(0, 3)) {
    lines.push(renderEvidenceBlock(f), '');
  }

  return {
    text: lines.join('\n').trimEnd(),
    referencedFindings: targets,
    referencedFiles: [...new Set(targets.map((f) => f.file).filter(Boolean))],
    referencedDomains: [],
  };
}

export function handleMetadata(audit: DeterministicAuditPayload): HandlerOutput {
  const sha7 = (audit.commitSha || '').slice(0, 7) || 'Not available for this audit run.';
  const sp = audit.sprite;

  const lines: string[] = [
    `Execution and sandbox metadata for **${audit.repo}#${audit.prNumber}** (commit \`${sha7}\`, status \`${audit.status}\`):`,
    '',
    `- **Repository & PR:** \`${audit.repo}#${audit.prNumber}\`${audit.branch ? ` on branch \`${audit.branch}\`` : ''}`,
    `- **Commit SHA:** \`${audit.commitSha || 'Not available for this audit run.'}\``,
    `- **Risk Score:** **${audit.riskScore}/100** (${audit.severity})`,
  ];

  if (!sp || (!sp.id && !sp.lifecycle && !sp.checkpoint && !sp.isolationSandbox)) {
    lines.push('- **Sandbox / Sprite:** Not available for this audit run.');
  } else {
    lines.push(`- **Sprite ID:** \`${sp.id || 'Not available for this audit run.'}\``);
    lines.push(`- **Sprite Lifecycle:** \`${sp.lifecycle || 'unknown'}\``);
    if (sp.checkpoint) lines.push(`- **Checkpoint:** \`${sp.checkpoint}\``);
    if (sp.durationMs !== null && sp.durationMs !== undefined) lines.push(`- **Execution Duration:** \`${sp.durationMs}ms\``);
    if (sp.runtimeEnv) lines.push(`- **Runtime Environment:** \`${sp.runtimeEnv}\``);
    if (sp.isolationSandbox) lines.push(`- **Isolation Sandbox:** \`${sp.isolationSandbox}\``);
  }

  return {
    text: lines.join('\n'),
    referencedFindings: [],
    referencedFiles: [],
    referencedDomains: [],
  };
}

export function handleFalsePositive(audit: DeterministicAuditPayload, entities: EntityResolution): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const targets = entities.matchedFindings.length > 0 ? entities.matchedFindings : sorted.slice(0, 3);

  const primary = targets[0];
  const confText =
    primary && primary.confidence !== null && primary.confidence !== undefined
      ? ` (${Math.round(primary.confidence * 100)}% confidence, source: \`${primary.source ?? 'static'}\`)`
      : primary?.source
        ? ` (source: \`${primary.source}\`)`
        : '';

  const lines: string[] = [
    primary
      ? `SpriteGuard cannot auto-dismiss **${primary.title}**${confText} from chat — security blocks require explicit code remediation or repository policy updates.`
      : `SpriteGuard cannot auto-dismiss security checks from chat — all overrides require explicit repository policy or maintainer PR review.`,
    '',
    '- **Why Not Auto-Dismissed:** Deterministic secret patterns and live runtime egress hooks represent high-confidence signals that stay enforced until resolved in git or allowlisted in policy.',
    '- **If This Is Intentional Egress:** Document and add the approved hostname to `SPRITE_EGRESS_ALLOWLIST` in your repository/deployment configuration.',
    '- **If This Is a Test Fixture Secret:** Move test fixtures into non-production mock values or inject them via CI environment variables rather than committing live-prefixed tokens.',
    '- **Maintainer Override:** Only repository maintainers with merge permissions can review and decide whether to bypass branch protection outside SpriteGuard.',
  ];

  return {
    text: lines.join('\n'),
    referencedFindings: targets,
    referencedFiles: [...new Set(targets.map((f) => f.file).filter(Boolean))],
    referencedDomains: [],
  };
}

export function handleNextSteps(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const hasSecrets = sorted.some(isSecretFinding);
  const patch = audit.patch;

  if (sorted.length === 0 && flaggedEgress.length === 0) {
    return handleCleanShortCircuit(audit);
  }

  const steps: string[] = [];
  if (hasSecrets) {
    const secretLocs = sorted
      .filter(isSecretFinding)
      .map((f) => `\`${locOf(f)}\``)
      .join(', ');
    steps.push(
      `Revoke and rotate all exposed credentials at the provider immediately (detected at ${secretLocs}) and squash/rewrite PR commits so secrets are removed from git history.`,
    );
  }

  if (patch && isPatchValidationPassing(patch.validationStatus) && patch.testStatus === 'passed' && !patch.pushed) {
    steps.push(
      `Comment \`/spriteguard approve\` on PR #${audit.prNumber} to commit the verified remediation patch via the Write Connector.`,
    );
  } else if (patch && patch.testStatus === 'failed') {
    const parsed = parseTestFailure(patch.testOutput);
    const errHint = parsed?.primaryError ? ` (\`${parsed.primaryError}\`)` : '';
    steps.push(
      `Fix the failing patch verification tests locally${errHint}, verify your test suite passes, and push a new commit to re-trigger SpriteGuard.`,
    );
  } else if (sorted.length > 0 && !patch) {
    steps.push(
      `Apply the remediation changes locally for ${sorted.map((f) => `\`${locOf(f)}\``).join(', ')}, verify tests pass, and push a new commit.`,
    );
  }

  if (flaggedEgress.length > 0 && (!patch || (patch.flaggedEgressAfterPatch ?? 0) > 0 || patch.testStatus === 'failed')) {
    steps.push(
      `Remove or explicitly allowlist the flagged outbound call(s) to ${flaggedEgress.map((e) => `\`${hostPortOf(e)}\``).join(', ')} before merging.`,
    );
  }

  if (steps.length === 0) {
    steps.push(`Review the audit report for PR #${audit.prNumber} and verify all checks pass before merging.`);
  }

  const lines = [
    `Follow these **${steps.length}** step${steps.length === 1 ? '' : 's'} to resolve PR #${audit.prNumber}:`,
    '',
    ...steps.map((s, i) => `${i + 1}. ${s}`),
  ];

  return {
    text: lines.join('\n'),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleDraft(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  return {
    text: draftEscalationComment(audit),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleQuantitative(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let secretCount = 0;
  let egressCount = 0;
  let otherCount = 0;

  for (const f of sorted) {
    if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++;
    if (isSecretFinding(f)) secretCount++;
    else if (isEgressFinding(f)) egressCount++;
    else otherCount++;
  }

  const totalFlaggedHits = flaggedEgress.reduce((acc, e) => acc + (e.hitCount || 0), 0);

  return {
    text: [
      `PR #${audit.prNumber} has **${sorted.length}** total finding${sorted.length === 1 ? '' : 's'} (risk **${audit.riskScore}/100**, ${audit.severity}) and **${flaggedEgress.length}** flagged outbound domain${flaggedEgress.length === 1 ? '' : 's'}.`,
      '',
      `- **By Severity:** \`${sevCounts.critical}\` critical · \`${sevCounts.high}\` high · \`${sevCounts.medium}\` medium · \`${sevCounts.low}\` low`,
      `- **By Category:** \`${secretCount}\` secret(s) · \`${egressCount}\` egress · \`${otherCount}\` other`,
      `- **Flagged Outbound Traffic:** \`${totalFlaggedHits}\` total hit(s) across \`${flaggedEgress.length}\` flagged domain(s)`,
    ].join('\n'),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleBoolean(
  nq: NormalizedQuery,
  audit: DeterministicAuditPayload,
  entities: EntityResolution,
): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const secrets = sorted.filter(isSecretFinding);
  const criticals = sorted.filter((f) => f.severity === 'critical');
  const patch = audit.patch;
  const q = nq.lower;

  // 1. Specific absent domain check (e.g., "any egress to google.com?")
  if (entities.absentDomains.length > 0 && entities.matchedDomains.length === 0) {
    return handleEgress(audit, entities);
  }

  // 2. Did tests pass?
  if (/\btests?\b/.test(q) && /\bpass\b/.test(nq.stemmedTokens.join(' '))) {
    const passed = patch?.testStatus === 'passed';
    const parsed = parseTestFailure(patch?.testOutput);
    if (!patch || !patch.testStatus || patch.testStatus === 'not_run' || patch.testStatus === 'skipped') {
      return {
        text: `No — patch verification tests did not run for PR #${audit.prNumber} (status: \`${formatStageLabel(patch?.testStatus, 'not_run')}\`).`,
        referencedFindings: [],
        referencedFiles: [],
        referencedDomains: [],
      };
    }
    if (passed) {
      return {
        text: `Yes — patch verification tests passed for PR #${audit.prNumber}${patch.testSummary ? ` (${patch.testSummary})` : ''}.`,
        referencedFindings: [],
        referencedFiles: [],
        referencedDomains: [],
      };
    }
    const lines = [
      `No — patch verification tests **failed** for PR #${audit.prNumber}${parsed?.exitCode !== null && parsed?.exitCode !== undefined ? ` with exit code \`${parsed.exitCode}\`` : ''}.`,
      '',
    ];
    if (parsed?.failingSuite) lines.push(`- **Failing Suite / Case:** \`${parsed.failingSuite}\``);
    if (parsed?.primaryError) lines.push(`- **Primary Error:** \`${parsed.primaryError}\``);
    if (!parsed) lines.push('- **Test Output:** Not available for this audit run.');
    return {
      text: lines.join('\n'),
      referencedFindings: sorted,
      referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
      referencedDomains: [],
      needsTruncatedTestHint: Boolean(parsed?.truncated),
    };
  }

  // 3. Is there a patch?
  if (/\b(?:is\s+there|have|has)\s+a?\s*(?:patch|fix)\b/i.test(nq.raw)) {
    if (patch) {
      return {
        text: `Yes — a \`${patch.status}\` remediation patch was generated (\`${formatStageLabel(patch.generator, 'heuristic')}\`, tests: \`${formatStageLabel(patch.testStatus, 'not_run')}\`).`,
        referencedFindings: sorted,
        referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
        referencedDomains: [],
      };
    }
    return {
      text: `No — no automated patch was generated for PR #${audit.prNumber}.`,
      referencedFindings: sorted,
      referencedFiles: [],
      referencedDomains: [],
    };
  }

  // 4. Any secrets / leaked keys?
  if (entities.requestedCategory === 'secret' || /\b(?:secret|key|credential|token|leak)\b/.test(nq.stemmedTokens.join(' '))) {
    if (secrets.length === 0) {
      return {
        text: `No — zero exposed secrets or credentials were detected in PR #${audit.prNumber}.`,
        referencedFindings: [],
        referencedFiles: [],
        referencedDomains: [],
      };
    }
    return {
      text: [
        `Yes — **${secrets.length}** exposed secret${secrets.length === 1 ? '' : 's'} detected in PR #${audit.prNumber}.`,
        '',
        ...secrets.map(
          (f) => `- **[${f.severity.toUpperCase()}] ${f.title}** at \`${locOf(f)}\`${f.redactedSecret ? ` (\`${f.redactedSecret}\`)` : ''}`,
        ),
        '- **Action:** Revoke and rotate every exposed key at the provider immediately.',
      ].join('\n'),
      referencedFindings: secrets,
      referencedFiles: [...new Set(secrets.map((f) => f.file).filter(Boolean))],
      referencedDomains: [],
    };
  }

  // 5. Any egress / c2 / exfil?
  if (entities.requestedCategory === 'egress' || /\b(?:egress|exfil|c2|domain|outbound|network|beacon)\b/.test(nq.stemmedTokens.join(' '))) {
    if (flaggedEgress.length === 0) {
      return {
        text: `No — zero unauthorized outbound egress destinations were flagged in PR #${audit.prNumber}.`,
        referencedFindings: [],
        referencedFiles: [],
        referencedDomains: [],
      };
    }
    return {
      text: [
        `Yes — **${flaggedEgress.length}** unauthorized outbound egress destination${flaggedEgress.length === 1 ? '' : 's'} flagged in PR #${audit.prNumber}.`,
        '',
        ...flaggedEgress.map(
          (e) => `- \`${hostPortOf(e)}\` — **${e.hitCount}** hit(s) during \`${e.phase}\` phase`,
        ),
      ].join('\n'),
      referencedFindings: sorted.filter(isEgressFinding),
      referencedFiles: [...new Set(sorted.filter(isEgressFinding).map((f) => f.file).filter(Boolean))],
      referencedDomains: flaggedEgress.map((e) => e.domain),
    };
  }

  // 6. Any criticals?
  if (/\bcritical\b/.test(nq.stemmedTokens.join(' '))) {
    if (criticals.length === 0) {
      return {
        text: `No — zero critical findings were recorded in PR #${audit.prNumber} (overall severity: ${audit.severity}).`,
        referencedFindings: [],
        referencedFiles: [],
        referencedDomains: [],
      };
    }
    return {
      text: [
        `Yes — **${criticals.length}** critical finding${criticals.length === 1 ? '' : 's'} detected in PR #${audit.prNumber}:`,
        '',
        ...criticals.map((f) => `- **${f.title}** at \`${locOf(f)}\``),
      ].join('\n'),
      referencedFindings: criticals,
      referencedFiles: [...new Set(criticals.map((f) => f.file).filter(Boolean))],
      referencedDomains: [],
    };
  }

  // 7. Blocked?
  if (/\bblock\b/.test(nq.stemmedTokens.join(' '))) {
    const isBlocked =
      sorted.length > 0 ||
      flaggedEgress.length > 0 ||
      patch?.testStatus === 'failed' ||
      audit.status === 'failed' ||
      audit.status === 'awaiting_approval';
    return {
      text: isBlocked
        ? `Yes — PR #${audit.prNumber} is blocked (status \`${audit.status}\`, risk **${audit.riskScore}/100**, ${sorted.length} finding(s), patch tests: \`${formatStageLabel(patch?.testStatus, 'not_run')}\`).`
        : `No — PR #${audit.prNumber} is not blocked (status \`${audit.status}\`, risk **${audit.riskScore}/100**).`,
      referencedFindings: sorted,
      referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
      referencedDomains: flaggedEgress.map((e) => e.domain),
    };
  }

  // 8. Is it safe / clean?
  const isClean = sorted.length === 0 && flaggedEgress.length === 0 && audit.riskScore === 0;
  return {
    text: isClean
      ? `Yes — PR #${audit.prNumber} is clean and safe to merge (risk **0/100**, 0 findings, 0 flagged egress).`
      : `No — PR #${audit.prNumber} is not safe to merge yet (risk **${audit.riskScore}/100** ${audit.severity}, ${sorted.length} finding(s), ${flaggedEgress.length} flagged egress, patch tests: \`${formatStageLabel(patch?.testStatus, 'not_run')}\`).`,
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleComparison(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  if (sorted.length === 0) {
    return handleCleanShortCircuit(audit);
  }
  const top = sorted[0]!;
  const lines: string[] = [
    `The highest-priority blocker in PR #${audit.prNumber} is **[${top.severity.toUpperCase()}] ${top.title}** at \`${locOf(top)}\`${top.riskContribution ? ` (+${top.riskContribution} risk)` : ''}.`,
    '',
    `- **Impact:** ${explainThreatImpact(top, audit.egressEvents ?? [])}`,
    `- **Fix First:** ${top.remediation || (isSecretFinding(top) ? 'Move the secret to an environment variable and revoke/rotate the leaked key immediately.' : `Remediate the issue at \`${locOf(top)}\` and re-run tests.`)}`,
  ];

  if (sorted.length > 1) {
    lines.push(
      `- **Next in Priority:** ${sorted
        .slice(1, 4)
        .map((f) => `[${f.severity.toUpperCase()}] ${f.title} (\`${locOf(f)}\`)`)
        .join('; ')}`,
    );
  }

  return {
    text: lines.join('\n'),
    referencedFindings: [top],
    referencedFiles: top.file ? [top.file] : [],
    referencedDomains: [],
  };
}

export function handleFullReport(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const breakdown = computeRiskBreakdown(audit);
  const patch = audit.patch;
  const parsed = parseTestFailure(patch?.testOutput);

  const lines: string[] = [
    `Full audit breakdown for **${audit.repo}#${audit.prNumber}** (commit \`${(audit.commitSha || '').slice(0, 7)}\`, status \`${audit.status}\`):`,
    '',
    '### 1) Risk Breakdown',
    `- **Score:** **${audit.riskScore}/100** (${audit.severity})${breakdown.length > 0 ? ` — ${breakdown.map((b) => `\`+${b.points}\` ${b.label}`).join(', ')}` : ''}`,
    '',
    '### 2) Findings by File',
  ];

  if (sorted.length === 0) {
    lines.push('- No findings recorded.');
  } else {
    for (const f of sorted) {
      lines.push(
        `- \`${locOf(f)}\` — **[${f.severity.toUpperCase()}] ${f.title}**${f.redactedSecret ? ` (\`${f.redactedSecret}\`)` : ''}`,
      );
    }
  }

  lines.push('', '### 3) Egress Events');
  if ((audit.egressEvents ?? []).length === 0) {
    lines.push('- No outbound external domains recorded.');
  } else {
    for (const ev of audit.egressEvents) {
      lines.push(
        `- \`${hostPortOf(ev)}\` — ${ev.flagged ? '**FLAGGED**' : 'allowlisted'} (${ev.hitCount} hit(s) in \`${ev.phase}\`)`,
      );
    }
  }

  lines.push('', '### 4) Patch Pipeline');
  if (!patch) {
    lines.push('- No automated patch generated.');
  } else {
    lines.push(
      `- Generated (\`${formatStageLabel(patch.generator, 'heuristic')}\`) -> Validated (\`${formatStageLabel(patch.validationStatus, 'pending')}\`) -> Tested (\`${formatStageLabel(patch.testStatus, 'not_run')}\`) -> Pushed (${patch.pushed ? 'yes' : 'no'})`,
    );
    if (patch.testStatus === 'failed' && parsed?.primaryError) {
      lines.push(`- **Test Failure:** \`${parsed.primaryError}\``);
    }
  }

  const next = handleNextSteps(audit);
  lines.push('', '### 5) Next Steps', ...next.text.split('\n').slice(2));

  return {
    text: lines.join('\n'),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleSummary(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flagged = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const secrets = sorted.filter(isSecretFinding);
  const hasSecrets = secrets.length > 0;
  const sha7 = (audit.commitSha || '').slice(0, 7) || 'unknown';

  if (sorted.length === 0 && flagged.length === 0) {
    return handleCleanShortCircuit(audit);
  }

  const reasons: string[] = [];
  if (hasSecrets) reasons.push(`${secrets.length} exposed credential${secrets.length === 1 ? '' : 's'}`);
  if (flagged.length > 0) reasons.push(`unauthorized outbound traffic to ${flagged.map((d) => `\`${d.domain}\``).join(', ')}`);
  const otherCount = sorted.filter((f) => !isSecretFinding(f) && !isEgressFinding(f)).length;
  if (otherCount > 0) reasons.push(`${otherCount} code security issue${otherCount === 1 ? '' : 's'}`);

  const sentences: string[] = [
    `PR **${audit.repo}#${audit.prNumber}** (\`${sha7}\`) was flagged at **${audit.riskScore}/100** (${audit.severity}) due to ${
      reasons.length > 0 ? reasons.join(' and ') : `${sorted.length} security finding${sorted.length === 1 ? '' : 's'}`
    }.`,
  ];
  if (audit.patch) {
    sentences.push(
      `A remediation patch is \`${audit.patch.status}\` (tests: \`${formatStageLabel(audit.patch.testStatus, 'not_run')}\`${audit.patch.testSummary ? `, ${audit.patch.testSummary}` : ''}).`,
    );
  }
  if (hasSecrets) {
    sentences.push(
      'Revoke and rotate the exposed credentials at the provider before merging, since code patches do not invalidate leaked keys.',
    );
  }

  const out: string[] = [sentences.join(' ')];

  if (sorted.length > 0) {
    out.push('');
    out.push('<details>');
    out.push(`<summary>Show all ${sorted.length} finding${sorted.length === 1 ? '' : 's'}</summary>`);
    out.push('');
    for (const f of sorted) {
      out.push(`- **[${f.severity.toUpperCase()}] ${f.title}** (\`${locOf(f)}\`): ${f.exploitability || f.title}`);
    }
    if (flagged.length > 0) {
      out.push(`- **Flagged Egress:** ${flagged.map((d) => `\`${hostPortOf(d)}\``).join(', ')}`);
    }
    if (audit.relatedIncidents && audit.relatedIncidents.length > 0) {
      out.push(
        `- **Related Past Incidents:** ${audit.relatedIncidents
          .slice(0, 3)
          .map((p) => `PR #${p.prNumber} (${p.title}, ${(p.similarity * 100).toFixed(0)}% match)`)
          .join('; ')}`,
      );
    }
    out.push('</details>');
  }

  return {
    text: out.join('\n'),
    referencedFindings: sorted,
    referencedFiles: [...new Set(sorted.map((f) => f.file).filter(Boolean))],
    referencedDomains: flagged.map((e) => e.domain),
  };
}

export function handleDisambiguation(audit: DeterministicAuditPayload): HandlerOutput {
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const patch = audit.patch;
  const top = sorted[0];

  if (!top && flaggedEgress.length === 0) {
    return handleCleanShortCircuit(audit);
  }

  const lines: string[] = [];
  if (patch?.testStatus === 'failed') {
    const parsed = parseTestFailure(patch.testOutput);
    lines.push(
      `The immediate blocker on PR #${audit.prNumber} is a **failing patch test**${parsed?.exitCode !== null && parsed?.exitCode !== undefined ? ` (exit code \`${parsed.exitCode}\`)` : ''}${top ? ` alongside the **[${top.severity.toUpperCase()}] ${top.title}** finding at \`${locOf(top)}\`` : ''}.`,
    );
    lines.push('');
    if (parsed?.failingSuite) lines.push(`- **Failing Suite / Case:** \`${parsed.failingSuite}\``);
    if (parsed?.primaryError) lines.push(`- **Primary Test Error:** \`${parsed.primaryError}\``);
  } else if (top) {
    lines.push(
      `The primary blocker on PR #${audit.prNumber} is **[${top.severity.toUpperCase()}] ${top.title}** at \`${locOf(top)}\` (overall risk **${audit.riskScore}/100**).`,
    );
    lines.push('');
  } else {
    lines.push(
      `The primary blocker on PR #${audit.prNumber} is unauthorized outbound egress to \`${hostPortOf(flaggedEgress[0]!)}\`.`,
    );
    lines.push('');
  }

  if (top) {
    lines.push(`- **Top Finding:** ${explainThreatImpact(top, audit.egressEvents ?? [])}`);
  }
  const suggestions = buildSuggestedQuestions(audit);
  lines.push(`- **Dig Deeper:** Try asking ${suggestions.slice(0, 3).map((s) => `"${s}"`).join(', ')}.`);

  return {
    text: lines.join('\n'),
    referencedFindings: top ? [top] : [],
    referencedFiles: top?.file ? [top.file] : [],
    referencedDomains: flaggedEgress.map((e) => e.domain),
  };
}

export function handleOutOfScope(audit: DeterministicAuditPayload): HandlerOutput {
  const suggestions = buildSuggestedQuestions(audit);
  const suggestionText = suggestions.map((s) => `'${s}'`).join(', ');
  return {
    text: [
      `${OFF_TOPIC_PREFIX} I cannot answer unrelated requests from PR #${audit.prNumber}'s audit payload.`,
      '',
      `- **Try asking:** ${suggestionText}`,
    ].join('\n'),
    referencedFindings: [],
    referencedFiles: [],
    referencedDomains: [],
  };
}

export function dispatchIntent(
  intent: IntentId,
  nq: NormalizedQuery,
  audit: DeterministicAuditPayload,
  entities: EntityResolution,
): HandlerOutput {
  switch (intent) {
    case 'secrets':
      return handleSecrets(audit, entities);
    case 'location':
      return handleLocation(audit, entities);
    case 'egress':
      return handleEgress(audit, entities);
    case 'fix':
      return handleFix(audit, entities);
    case 'exploit':
      return handleExploit(audit, entities);
    case 'approve':
      return handleApprove(audit);
    case 'diff':
      return handleDiff(audit, entities);
    case 'evidence':
      return handleEvidence(audit, entities);
    case 'metadata':
      return handleMetadata(audit);
    case 'false_positive':
      return handleFalsePositive(audit, entities);
    case 'next_steps':
      return handleNextSteps(audit);
    case 'draft':
      return handleDraft(audit);
    case 'quantitative':
      return handleQuantitative(audit);
    case 'boolean':
      return handleBoolean(nq, audit, entities);
    case 'comparison':
      return handleComparison(audit);
    case 'full_report':
      return handleFullReport(audit);
    case 'summary':
      return handleSummary(audit);
  }
}

export const INTENT_SECTION_TITLE: Readonly<Record<IntentId, string>> = {
  secrets: 'Exposed Secrets & Credentials',
  location: 'Flagged Locations',
  egress: 'Outbound Egress & Network',
  fix: 'Patch & Test Diagnostics',
  exploit: 'Risk & Exploitability',
  approve: 'Approval & Merge Eligibility',
  diff: 'Proposed Patch Diff',
  evidence: 'Code Evidence',
  metadata: 'Sandbox & PR Metadata',
  false_positive: 'False Positives & Policy Overrides',
  next_steps: 'Next Steps',
  draft: 'Team Escalation Draft',
  quantitative: 'Counts & Breakdown',
  boolean: 'Status Check',
  comparison: 'Top Priority Blocker',
  full_report: 'Full Audit Report',
  summary: 'Audit Summary',
};
