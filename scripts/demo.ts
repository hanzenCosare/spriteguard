import { loadConfig } from '../src/config.js';
import { createVulnerablePrFixture } from '../src/demoFixtures.js';
import { createApp } from '../src/index.js';

async function main(): Promise<void> {
  const cfg = loadConfig({
    ...process.env,
    LOCAL_SANDBOX_MODE: 'true',
    LOCAL_ALLOW_UNTRUSTED_EXEC: 'true',
  });

  const sg = await createApp(cfg);
  try {
    if (!sg.connectors.simulator) {
      throw new Error('Demo requires LOCAL_SANDBOX_MODE without GitHub App tokens so the local GitHub simulator runs.');
    }

    const pr = createVulnerablePrFixture(sg.connectors.simulator);
    console.log(`\n=== 1. Triggering Zero-Trust Audit for ${pr.repoFullName}#${pr.number} (${pr.headSha.slice(0, 7)}) ===`);

    const scan = await sg.orchestrator.runPullRequestAudit(pr.repoFullName, pr.number);
    const patch = await sg.store.getPatch(scan.id);

    console.log(`Scan ID:       ${scan.id}`);
    console.log(`Status:        ${scan.status}`);
    console.log(`Risk Score:    ${scan.riskScore}/100 (${scan.severity})`);
    console.log(`Findings:      ${scan.findingsCount} (${scan.secretsCount} secret leak(s))`);
    console.log(`Flagged Egress:${scan.flaggedEgressCount} domain(s) -> ${scan.egressDomains.filter((d) => d.flagged).map((d) => d.host).join(', ') || 'none'}`);
    console.log(`Sprite State:  ${scan.spriteState} (checkpoint: ${scan.checkpointId ?? 'none'})`);

    if (patch) {
      console.log(`\n=== 2. Autonomous Verified Patch (${patch.generator}, status=${patch.status}) ===`);
      console.log(`Diff SHA-256:  ${patch.diffSha256}`);
      console.log(`Tests Before:  ${patch.verification?.testsBefore.summary}`);
      console.log(`Tests After:   ${patch.verification?.testsAfter.summary}`);
      console.log(`\n${patch.diff}`);
    }

    console.log('\n=== 3. Interactive @spriteguard Q&A ===');
    const qa = await sg.orchestrator.handleQuestion(
      pr.repoFullName,
      pr.number,
      'alice-maintainer',
      'What outbound network domains were flagged and did tests pass after the patch?',
    );
    console.log(qa.answer);

    console.log('\n=== 4. Unauthorized Approval Attempt (mallory-contributor) ===');
    const denied = await sg.orchestrator.handleApproval(pr.repoFullName, pr.number, 'mallory-contributor');
    console.log(`Denied ok=${denied.ok}: ${denied.reason}`);

    console.log('\n=== 5. Maintainer Approval (/spriteguard approve by alice-maintainer) ===');
    const approved = await sg.orchestrator.handleApproval(pr.repoFullName, pr.number, 'alice-maintainer');
    const finalScan = await sg.store.getScan(scan.id);
    console.log(`Approved ok=${approved.ok} | Commit SHA=${approved.commitSha}`);
    console.log(`Final Scan Status=${finalScan?.status} | Sprite State=${finalScan?.spriteState}`);
  } finally {
    await sg.close();
  }
}

void main();
