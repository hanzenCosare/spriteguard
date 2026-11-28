import { isEgressFinding, isSecretFinding, sortFindingsByPriority } from './entities.js';
import { languageForFile } from './logParser.js';
import type {
  DeterministicAuditPayload,
  DeterministicEgressEvent,
  DeterministicFinding,
} from './types.js';

/**
 * Layer 4 Offline Intelligence:
 *  - Language-aware deterministic remediation code snippet synthesizer
 *  - Rule-based Threat Matrix (blast radius & attack vector explainer)
 *  - Copy-pasteable PR comment / Slack escalation drafter
 */

export function deriveEnvVarName(finding: DeterministicFinding): string {
  const ev = finding.evidence ?? '';
  // Look for JS/TS/Py/Go/Env variable assignment in evidence
  const assignMatch =
    /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(ev) ??
    /^\s*([A-Z][A-Z0-9_]{2,})\s*[:=]/.exec(ev) ??
    /\b([a-zA-Z_][a-zA-Z0-9_]*(?:key|secret|token|password|passwd|url|dsn|cred|auth)[a-zA-Z0-9_]*)\s*[:=]/i.exec(ev);

  if (assignMatch?.[1]) {
    const raw = assignMatch[1];
    return raw
      .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      .replace(/[^A-Za-z0-9_]+/g, '_')
      .toUpperCase();
  }

  const t = (finding.title || '').toLowerCase();
  if (t.includes('stripe') && t.includes('webhook')) return 'STRIPE_WEBHOOK_SECRET';
  if (t.includes('stripe')) return 'STRIPE_SECRET_KEY';
  if (t.includes('aws') && t.includes('secret')) return 'AWS_SECRET_ACCESS_KEY';
  if (t.includes('aws')) return 'AWS_ACCESS_KEY_ID';
  if (t.includes('github')) return 'GITHUB_TOKEN';
  if (t.includes('anthropic')) return 'ANTHROPIC_API_KEY';
  if (t.includes('openai')) return 'OPENAI_API_KEY';
  if (t.includes('slack')) return 'SLACK_BOT_TOKEN';
  if (t.includes('database') || t.includes('postgres')) return 'DATABASE_URL';
  if (t.includes('google') || t.includes('gemini')) return 'GOOGLE_API_KEY';

  const derived = finding.title
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()
    .slice(0, 32);
  return derived || 'APP_SECRET_KEY';
}

export function synthesizeRemediationSnippet(
  finding: DeterministicFinding,
  egressEvents: readonly DeterministicEgressEvent[],
): string {
  const file = finding.file || 'file';
  const loc = finding.line > 0 ? `${file}:${finding.line}` : file;
  const base = file.split('/').pop()?.toLowerCase() ?? '';
  const ext = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : '';
  const isEnvLike = base.startsWith('.env') || ['yml', 'yaml', 'json', 'toml'].includes(ext);

  if (isSecretFinding(finding)) {
    const varName = deriveEnvVarName(finding);

    if (isEnvLike) {
      return [
        `Remove tracked credentials from \`${file}\` and inject \`${varName}\` via runtime secrets:`,
        '```bash',
        `git rm --cached ${file}`,
        `echo "${base.startsWith('.env') ? '.env*' : file}" >> .gitignore`,
        `# Inject at runtime (e.g. Fly.io / CI secret manager):`,
        `fly secrets set ${varName}="<rotated-value>"`,
        '```',
        'Rotate and revoke the exposed credential immediately at the provider and squash leaked commits from PR history.',
      ].join('\n');
    }

    if (['js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs'].includes(ext)) {
      const lang = ext.startsWith('ts') ? 'typescript' : 'javascript';
      return [
        `Replace the hardcoded secret at \`${loc}\` with a guarded environment variable lookup:`,
        `\`\`\`${lang}`,
        `const ${varName} = process.env.${varName};`,
        `if (!${varName}) {`,
        `  throw new Error('Missing required environment variable: ${varName}');`,
        `}`,
        '```',
        'Add a placeholder to `.env.example`:',
        '```dotenv',
        `${varName}=replace_me`,
        '```',
      ].join('\n');
    }

    if (ext === 'py') {
      return [
        `Replace the hardcoded secret at \`${loc}\` using \`os.environ.get\`:`,
        '```python',
        'import os',
        '',
        `${varName} = os.environ.get("${varName}")`,
        `if not ${varName}:`,
        `    raise RuntimeError("Missing required environment variable: ${varName}")`,
        '```',
        'Add a placeholder to `.env.example`:',
        '```dotenv',
        `${varName}=replace_me`,
        '```',
      ].join('\n');
    }

    if (ext === 'go') {
      return [
        `Replace the hardcoded secret at \`${loc}\` using \`os.Getenv\`:`,
        '```go',
        `val := os.Getenv("${varName}")`,
        'if val == "" {',
        `    return fmt.Errorf("missing required environment variable: ${varName}")`,
        '}',
        '```',
        'Add a placeholder to `.env.example`:',
        '```dotenv',
        `${varName}=replace_me`,
        '```',
      ].join('\n');
    }

    const lang = languageForFile(file);
    const lookupLine =
      ext === 'rb'
        ? `${varName.toLowerCase()} = ENV.fetch("${varName}")`
        : ext === 'rs'
          ? `let ${varName.toLowerCase()} = std::env::var("${varName}")?;`
          : ext === 'java'
            ? `String ${varName.toLowerCase()} = Objects.requireNonNull(System.getenv("${varName}"), "Missing ${varName}");`
            : ext === 'sh' || ext === 'bash'
              ? `: "\${${varName}:?Missing required environment variable ${varName}}"`
              : `${varName} = ENV["${varName}"]`;

    return [
      `Replace the literal secret at \`${loc}\` with a runtime environment lookup:`,
      `\`\`\`${lang}`,
      lookupLine,
      '```',
      `Add \`${varName}=replace_me\` to \`.env.example\` and revoke/rotate the leaked credential at the provider.`,
    ].join('\n');
  }

  if (isEgressFinding(finding)) {
    const matchedEv =
      egressEvents.find((e) => e.associatedFindingId === finding.id) ??
      egressEvents.find((e) => e.flagged && `${finding.title} ${finding.evidence ?? ''} ${finding.runtimeProof ?? ''}`.toLowerCase().includes(e.domain.toLowerCase())) ??
      egressEvents.find((e) => e.flagged);

    const targetHost = matchedEv
      ? `${matchedEv.domain}${matchedEv.port ? `:${matchedEv.port}` : ''}`
      : 'the unauthorized external host';

    if (ext === 'py') {
      return [
        `Remove the unauthorized outbound call to \`${targetHost}\` at \`${loc}\`, or gate it behind an explicit hostname allowlist:`,
        '```python',
        'from urllib.parse import urlparse',
        '',
        'ALLOWED_EGRESS_HOSTS = {"api.internal.example"}  # Never serialize os.environ in payloads',
        'def safe_post(url: str, payload: dict):',
        '    host = urlparse(url).hostname',
        '    if host not in ALLOWED_EGRESS_HOSTS:',
        '        raise ValueError(f"Blocked unauthorized egress host: {host}")',
        '```',
      ].join('\n');
    }

    if (ext === 'go') {
      return [
        `Remove the unauthorized outbound call to \`${targetHost}\` at \`${loc}\`, or enforce an explicit host allowlist:`,
        '```go',
        'allowedHosts := map[string]bool{"api.internal.example": true}',
        'u, err := url.Parse(endpoint)',
        'if err != nil || !allowedHosts[u.Hostname()] {',
        '    return fmt.Errorf("blocked unauthorized egress host: %q", u.Hostname())',
        '}',
        '```',
      ].join('\n');
    }

    const lang = ext.startsWith('ts') ? 'typescript' : 'javascript';
    return [
      `Remove the unauthorized outbound call to \`${targetHost}\` at \`${loc}\`, or restrict requests to an explicit allowlist (never serializing \`process.env\`):`,
      `\`\`\`${lang}`,
      `const ALLOWED_EGRESS_HOSTS = new Set(['api.internal.example']);`,
      `export async function sendApprovedTelemetry(endpoint, safePayload) {`,
      `  const { hostname } = new URL(endpoint);`,
      `  if (!ALLOWED_EGRESS_HOSTS.has(hostname)) {`,
      `    throw new Error(\`Blocked unauthorized egress host: \${hostname}\`);`,
      `  }`,
      `  return fetch(endpoint, { method: 'POST', body: JSON.stringify(safePayload) });`,
      `}`,
      '```',
    ].join('\n');
  }

  if (finding.category === 'injection' && ['js', 'ts', 'mjs', 'cjs'].includes(ext)) {
    return [
      `Replace shell string interpolation at \`${loc}\` with parameterized \`execFile\` (no shell evaluation):`,
      '```javascript',
      "import { execFile } from 'node:child_process';",
      'execFile(binary, [validatedArg], { shell: false }, callback);',
      '```',
    ].join('\n');
  }

  return finding.remediation
    ? `At \`${loc}\`: ${finding.remediation}`
    : `Review and remediate the ${finding.severity} finding at \`${loc}\` locally and re-run the test suite.`;
}

/**
 * Rule-Based Threat Matrix: maps finding attributes to concrete attack vectors & blast radius.
 */
export function explainThreatImpact(
  finding: DeterministicFinding,
  egressEvents: readonly DeterministicEgressEvent[],
): string {
  const loc = finding.line > 0 ? `\`${finding.file}:${finding.line}\`` : `\`${finding.file}\``;

  if (isSecretFinding(finding)) {
    const red = (finding.redactedSecret ?? '').toLowerCase();
    const titleLow = (finding.title ?? '').toLowerCase();
    const isStripeLive = red.startsWith('sk_live') || (red.startsWith('sk_l') && !red.includes('test')) || titleLow.includes('stripe');
    const isAws = red.startsWith('akia') || red.startsWith('asia') || titleLow.includes('aws');
    const isGitHub = red.startsWith('ghp_') || red.startsWith('github_pat_') || titleLow.includes('github');
    const isSlack = red.startsWith('xoxb-') || red.startsWith('xoxp-') || titleLow.includes('slack');
    const isGoogle = red.startsWith('aiza') || titleLow.includes('google') || titleLow.includes('gcp');
    const isPrivKey = red.includes('private key') || titleLow.includes('private key');

    let blast = 'unauthorized API/service access, data exfiltration, or account takeover';
    if (isStripeLive) blast = 'unauthorized live billing charges, refunds, customer data access, and financial loss';
    else if (isAws) blast = 'cloud infrastructure compromise, S3/database exfiltration, and privilege escalation';
    else if (isGitHub) blast = 'unauthorized repository access, malicious commits, and CI/CD supply-chain compromise';
    else if (isSlack) blast = 'workspace message exfiltration and phishing/lateral movement across Slack channels';
    else if (isGoogle) blast = 'unauthorized cloud API consumption, billing abuse, and project resource access';
    else if (isPrivKey) blast = 'cryptographic impersonation, TLS/SSH compromise, and token forgery';

    return `**${finding.title}** at ${loc} (${finding.severity.toUpperCase()}): Production/live credential exposure creates immediate risk of ${blast}. Secrets committed to git history remain harvestable even after a follow-up deletion commit until revoked and rotated at the provider.`;
  }

  if (isEgressFinding(finding)) {
    const ev =
      egressEvents.find((e) => e.associatedFindingId === finding.id) ??
      egressEvents.find((e) => e.flagged && `${finding.title} ${finding.evidence ?? ''} ${finding.runtimeProof ?? ''}`.toLowerCase().includes(e.domain.toLowerCase())) ??
      egressEvents.find((e) => e.flagged);

    const hostLabel = ev ? `\`${ev.domain}${ev.port ? `:${ev.port}` : ''}\`` : 'an unapproved external host';
    const hits = ev ? ev.hitCount : 1;
    const phase = (ev?.phase ?? '').toLowerCase();

    if (phase === 'install') {
      return `**${finding.title}** at ${loc} (${finding.severity.toUpperCase()}): **Supply-Chain / Build-Time Execution** vector — untrusted code contacts ${hostLabel} (${hits} hit(s)) automatically during dependency installation before tests or human review run, risking developer/CI credential theft.`;
    }
    if (phase === 'test') {
      return `**${finding.title}** at ${loc} (${finding.severity.toUpperCase()}): **CI/CD Sandbox Exfiltration** vector — active outbound network callback to ${hostLabel} was observed ${hits} time(s) during test execution, capable of exfiltrating environment variables, CI tokens, or source code.`;
    }
    return `**${finding.title}** at ${loc} (${finding.severity.toUpperCase()}): **Unauthorized Runtime Egress** vector — outbound traffic to ${hostLabel} (${hits} hit(s) in \`${ev?.phase ?? 'runtime'}\` phase) bypasses network policy and enables silent data exfiltration.`;
  }

  const contrib = finding.riskContribution ? ` (+${finding.riskContribution} risk)` : '';
  const detail = finding.exploitability || finding.evidence || 'Exploitable code path detected during audit.';
  return `**${finding.title}** at ${loc} (${finding.severity.toUpperCase()}${contrib}): ${detail}`;
}

export function draftEscalationComment(audit: DeterministicAuditPayload): string {
  const sha7 = (audit.commitSha || '').slice(0, 7) || 'unknown';
  const sorted = sortFindingsByPriority(audit.findings ?? []);
  const flaggedEgress = (audit.egressEvents ?? []).filter((e) => e.flagged);
  const hasSecrets = sorted.some(isSecretFinding);
  const patch = audit.patch;
  const valOk = patch?.validationStatus === 'passed' || patch?.validationStatus === 'verified';
  const testOk = patch?.testStatus === 'passed';
  const gateStatus =
    sorted.length === 0 && flaggedEgress.length === 0
      ? 'READY'
      : valOk && testOk && !hasSecrets
        ? 'READY (Approval Required)'
        : 'BLOCKED';

  const mdLines: string[] = [
    `### SpriteGuard Security Summary — ${audit.repo}#${audit.prNumber} (\`${sha7}\`)`,
    '',
    `- **Risk Score:** **${audit.riskScore}/100** (${audit.severity})`,
    `- **Merge Gate:** \`${gateStatus}\` (status: \`${audit.status}\`)`,
    '',
  ];

  if (sorted.length > 0) {
    mdLines.push('| File:Line | Severity | Category | Detail |');
    mdLines.push('| --- | --- | --- | --- |');
    for (const f of sorted) {
      const loc = f.line > 0 ? `\`${f.file}:${f.line}\`` : `\`${f.file}\``;
      const detail = f.redactedSecret
        ? `${f.title} (\`${f.redactedSecret}\`)`
        : f.title;
      mdLines.push(`| ${loc} | ${f.severity.toUpperCase()} | ${f.category} | ${detail} |`);
    }
    mdLines.push('');
  }

  if (flaggedEgress.length > 0) {
    mdLines.push('**Flagged Outbound Egress:**');
    for (const ev of flaggedEgress) {
      mdLines.push(
        `- \`${ev.domain}${ev.port ? `:${ev.port}` : ''}\` (${ev.hitCount} hit(s) in \`${ev.phase}\` phase)`,
      );
    }
    mdLines.push('');
  }

  mdLines.push('**Required Actions:**');
  if (hasSecrets) {
    mdLines.push('- [ ] Revoke and rotate all exposed credentials at the provider and squash leaked commits from PR history.');
  }
  if (patch && patch.testStatus === 'failed') {
    mdLines.push('- [ ] Fix failing patch verification tests locally and push a new commit to re-run SpriteGuard.');
  } else if (patch && valOk && testOk) {
    mdLines.push(`- [ ] Comment \`/spriteguard approve\` on PR #${audit.prNumber} to commit the verified patch.`);
  } else if (flaggedEgress.length > 0) {
    mdLines.push('- [ ] Remove or explicitly allowlist the flagged outbound network call before merging.');
  } else if (sorted.length === 0 && flaggedEgress.length === 0) {
    mdLines.push('- [x] No security blockers detected — safe to proceed with normal code review.');
  }

  return [
    `Here is a ready-to-paste security escalation summary for **${audit.repo}#${audit.prNumber}** (\`${gateStatus}\`):`,
    '',
    '```markdown',
    ...mdLines,
    '```',
  ].join('\n');
}
