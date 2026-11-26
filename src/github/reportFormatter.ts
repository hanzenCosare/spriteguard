import type { PatchRecord, ScanRecord, ScanReport, Severity, SeverityBadge } from '../types.js';

/**
 * GitHub-Flavored Markdown Security Audit Report & PR comment formatters.
 */

const BADGE_ICON: Record<SeverityBadge, string> = {
  Low: '🟢 LOW',
  Medium: '🟡 MEDIUM',
  High: '🟠 HIGH',
  Critical: '🔴 CRITICAL',
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴 CRITICAL',
  high: '🟠 HIGH',
  medium: '🟡 MEDIUM',
  low: '🔵 LOW',
  info: '⚪ INFO',
};

function escapeMd(text: string): string {
  return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderRiskBar(score: number): string {
  const filled = Math.max(0, Math.min(10, Math.round(score / 10)));
  return `[${'█'.repeat(filled)}${'░'.repeat(10 - filled)}] **${score}/100**`;
}

export function scanReportMarker(scanId: string, headSha: string): string {
  return `<!-- spriteguard-audit:scan=${scanId}:sha=${headSha} -->`;
}

export interface FormatAuditReportOptions {
  dashboardUrl?: string;
}

export function formatAuditReport(
  scan: ScanRecord,
  report: ScanReport,
  patch: PatchRecord | null,
  opts: FormatAuditReportOptions = {},
): string {
  const { audit, egress, pastIncidents } = report;
  const flaggedDomains = egress.domains.filter((d) => d.flagged);
  const badge = BADGE_ICON[audit.severity];

  const lines: string[] = [
    scanReportMarker(scan.id, scan.headSha),
    `## 🛡️ SpriteGuard Zero-Trust Security Audit`,
    '',
    `**PR Risk Score:** ${renderRiskBar(audit.riskScore)} &nbsp;|&nbsp; **Severity:** \`${badge}\` &nbsp;|&nbsp; **Commit:** \`${scan.headSha.slice(0, 7)}\``,
    '',
    `> ${escapeMd(audit.summary)}`,
    '',
    '| Metric | Value |',
    '| --- | --- |',
    `| Findings | **${audit.findings.length}** (${report.staticLeaks.length} secret/credential leak(s)) |`,
    `| Outbound Egress | **${egress.domains.length}** external domain(s), **${flaggedDomains.length}** flagged |`,
    `| Isolation Sandbox | \`${report.sandbox.driver}\` (\`${report.sandbox.spriteName}\`) |`,
    `| Sprite Lifecycle | \`${scan.spriteState}\` ${scan.checkpointId ? `(checkpoint \`${scan.checkpointId}\`)` : ''} |`,
    `| Audit Engine | \`${audit.model}\` |`,
    '',
  ];

  if (egress.canaryExfiltrations.length > 0) {
    lines.push(
      `> [!CAUTION]`,
      `> **Canary Secret Exfiltration Detected (${egress.canaryExfiltrations.length}):** Synthetic environment credentials injected inside the isolated Sprite were accessed and leaked at runtime:`,
      ...egress.canaryExfiltrations.map((c) => `> - **${c.channel}** (\`${c.canary}\`): ${escapeMd(c.detail)}`),
      '',
    );
  }

  lines.push(`### 🔍 Exploitability Evidence`);
  lines.push('');
  if (audit.findings.length === 0) {
    lines.push('No exploitable vulnerabilities or credential leaks were identified in this revision.');
    lines.push('');
  } else {
    for (const f of audit.findings) {
      const loc = f.line > 0 ? `\`${f.file}:${f.line}\`` : `\`${f.file}\``;
      lines.push(`#### ${SEVERITY_ICON[f.severity]} — ${escapeMd(f.title)}`);
      lines.push(`- **Location:** ${loc} &nbsp;|&nbsp; **Category:** \`${f.category}\` &nbsp;|&nbsp; **Source:** \`${f.source}\` &nbsp;|&nbsp; **Confidence:** ${Math.round(f.confidence * 100)}%`);
      lines.push(`- **Evidence:** \`${f.evidence.replace(/`/g, "'")}\``);
      lines.push(`- **Why It's Exploitable:** ${escapeMd(f.exploitability)}`);
      if (f.runtimeProof) {
        lines.push(`- **Runtime Proof:** ${escapeMd(f.runtimeProof)}`);
      }
      lines.push(`- **Remediation:** ${escapeMd(f.remediation)}`);
      lines.push('');
    }
  }

  lines.push(`### 🌐 Network Egress Summary`);
  lines.push('');
  if (egress.skipped) {
    lines.push(`_${escapeMd(egress.skipped)}_`);
    lines.push('');
  } else if (egress.domains.length === 0) {
    lines.push('No external outbound network connections were observed during dependency install, build, or test execution.');
    lines.push('');
  } else {
    const verdictByHost = new Map(audit.egressAssessment.map((v) => [v.domain.toLowerCase(), v]));
    lines.push('| Domain / IP | Ports | Phases | Hits | Status | Assessment |');
    lines.push('| --- | --- | --- | ---: | --- | --- |');
    for (const d of egress.domains) {
      const verdict = verdictByHost.get(d.host.toLowerCase());
      const statusBadge = d.flagged ? '🚨 Flagged' : '✅ Allowlisted';
      const detail = verdict
        ? `**${verdict.verdict}**: ${escapeMd(verdict.reason)}`
        : escapeMd(d.reasons.join('; ') || 'Expected package/tooling traffic');
      lines.push(
        `| \`${d.host}\` | ${d.ports.join(', ') || '—'} | ${d.phases.join(', ')} | ${d.hits} | ${statusBadge} | ${detail} |`,
      );
    }
    lines.push('');
  }

  if (pastIncidents.length > 0) {
    lines.push(`### 🧠 Semantic Memory — Similar Past Incidents (Neon pgvector)`);
    lines.push('');
    lines.push('| Past PR | Severity | File | Similarity | Finding |');
    lines.push('| --- | --- | --- | ---: | --- |');
    for (const inc of pastIncidents) {
      lines.push(
        `| #${inc.prNumber} | \`${inc.severity.toUpperCase()}\` | \`${inc.filePath}\` | ${(inc.similarity * 100).toFixed(0)}% | ${escapeMd(inc.title)} |`,
      );
    }
    lines.push('');
  }

  lines.push(`### 🔧 Autonomous Patch & Verification`);
  lines.push('');
  if (!patch) {
    if (audit.findings.length === 0) {
      lines.push('✅ Repository revision is clean — no remediation patch required.');
    } else {
      lines.push('⚠️ Manual review required — no automated patch was generated for the findings above.');
    }
    lines.push('');
  } else {
    const v = patch.verification;
    const verLabel =
      v?.status === 'verified'
        ? '✅ Verified Clean (tests & security re-scan passed)'
        : v?.status === 'verified_with_warnings'
          ? '⚠️ Verified with Warnings'
          : '❌ Verification Failed';

    lines.push(`- **Patch Status:** ${verLabel} (generator: \`${patch.generator}\`, diff SHA-256: \`${patch.diffSha256.slice(0, 12)}\`)`);
    lines.push(`- **Summary:** ${escapeMd(patch.summary)}`);
    if (v) {
      lines.push(`- **Tests Before Patch:** ${escapeMd(v.testsBefore.summary)}`);
      lines.push(`- **Tests After Patch:** ${escapeMd(v.testsAfter.summary)}`);
      lines.push(
        `- **Leaks Resolved:** ${v.resolvedFingerprints.length} &nbsp;|&nbsp; **Remaining Head Leaks:** ${v.remainingLeaks.length} &nbsp;|&nbsp; **Flagged Egress After Patch:** ${v.flaggedEgressAfter.length}`,
      );
      if (v.notes.length > 0) {
        for (const note of v.notes) {
          lines.push(`- **Note:** ${escapeMd(note)}`);
        }
      }
    }
    lines.push('');
    lines.push('<details>');
    lines.push('<summary><strong>Proposed Verified Patch Diff (click to expand)</strong></summary>');
    lines.push('');
    lines.push('```diff');
    lines.push(patch.diff.slice(0, 45_000));
    lines.push('```');
    lines.push('');
    if (patch.postMergeActions.length > 0) {
      lines.push('**Required Post-Merge Key Rotation / Actions:**');
      for (const act of patch.postMergeActions) {
        lines.push(`- [ ] ${escapeMd(act)}`);
      }
      lines.push('');
    }
    lines.push('</details>');
    lines.push('');
  }

  lines.push(`### 💬 Human-in-the-Loop Controls`);
  lines.push('');
  if (patch && (patch.status === 'verified' || patch.status === 'verified_with_warnings')) {
    lines.push(
      `- **Approve & Commit Patch:** Maintainers can comment \`/spriteguard approve\` to wake Sprite \`${report.sandbox.spriteName}\`, cross-verify the patch SHA-256, and commit the fix via the isolated GitHub Write Connector.`,
    );
  }
  lines.push(`- **Ask Questions:** Comment \`@spriteguard <your question>\` to query Claude Opus grounded in this scan's evidence.`);
  lines.push(`- **Re-run Audit:** Comment \`/spriteguard rescan\` to spin up a fresh Sprite and re-audit.`);
  if (opts.dashboardUrl) {
    lines.push(`- **Live Dashboard:** [Open SpriteGuard Console](${opts.dashboardUrl})`);
  }

  return lines.join('\n');
}

export function formatQaReply(question: string, answer: string, scan: ScanRecord): string {
  const shortQ = question.trim().slice(0, 160).replace(/\r?\n/g, ' ');
  return [
    `### 🤖 SpriteGuard Answer`,
    `> **Question:** ${escapeMd(shortQ)}`,
    `> **Grounded Scan:** \`${scan.id.slice(0, 8)}\` (commit \`${scan.headSha.slice(0, 7)}\`, Risk Score **${scan.riskScore ?? 0}/100**)`,
    '',
    answer,
  ].join('\n');
}

export function formatApprovalSuccess(
  scan: ScanRecord,
  patch: PatchRecord,
  commitSha: string,
  approver: string,
): string {
  const lines = [
    `### ✅ SpriteGuard Patch Approved & Committed`,
    '',
    `- **Approved By:** @${approver}`,
    `- **Committed Fix:** \`${commitSha}\` on branch \`${scan.headRef}\``,
    `- **Verified Diff SHA-256:** \`${patch.diffSha256}\``,
    `- **Sprite Lifecycle:** Sprite \`${scan.spriteName ?? 'ephemeral'}\` woken, verified, and destroyed.`,
    '',
  ];
  if (patch.postMergeActions.length > 0) {
    lines.push('**Important Post-Merge Actions:**');
    for (const action of patch.postMergeActions) {
      lines.push(`- [ ] ${escapeMd(action)}`);
    }
  }
  return lines.join('\n');
}

export function formatApprovalDenied(approver: string, reason: string): string {
  return [
    `### ⛔ SpriteGuard Approval Rejected`,
    '',
    `@${approver} — ${escapeMd(reason)}`,
  ].join('\n');
}

export function formatAuditError(repoFullName: string, prNumber: number, headSha: string, message: string): string {
  return [
    `### ⚠️ SpriteGuard Audit Failed`,
    '',
    `An error occurred while auditing **${repoFullName}#${prNumber}** (\`${headSha.slice(0, 7)}\`):`,
    '',
    '```',
    message.slice(0, 1500),
    '```',
    '',
    'Comment `/spriteguard rescan` to retry.',
  ].join('\n');
}
