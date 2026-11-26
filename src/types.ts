/**
 * Shared domain types for the SpriteGuard pipeline.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SeverityBadge = 'Low' | 'Medium' | 'High' | 'Critical';

export type SecretSource = 'diff' | 'commit' | 'env_file' | 'build_output' | 'runtime_output' | 'patched_tree';

export interface SecretLeak {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  source: SecretSource;
  file: string;
  line: number;
  commitSha?: string;
  /** Redacted representation, safe to display. Raw secrets are never persisted. */
  redacted: string;
  /** sha256 fingerprint (first 16 hex chars) of the raw secret, used for de-duplication & verification. */
  fingerprint: string;
  entropy: number;
  /** The offending line with the secret redacted. */
  context: string;
}

export type EgressEventKind = 'dns' | 'connect' | 'http' | 'socket' | 'strace';

export interface EgressEvent {
  kind: EgressEventKind;
  host: string;
  port?: number;
  url?: string;
  phase: string;
  via: string;
}

export interface EgressDomain {
  host: string;
  ports: number[];
  phases: string[];
  hits: number;
  allowlisted: boolean;
  flagged: boolean;
  reasons: string[];
  sampleUrls: string[];
}

export interface CommandRun {
  label: string;
  command: string;
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  stdoutTail: string;
  stderrTail: string;
}

export interface CanaryHit {
  canary: string;
  channel: 'stdout' | 'stderr' | 'egress_url';
  detail: string;
}

export type ProjectType = 'node' | 'python' | 'unknown';

export interface EgressReport {
  projectType: ProjectType;
  commands: CommandRun[];
  domains: EgressDomain[];
  rawIps: string[];
  runtimeLeaks: SecretLeak[];
  canaryExfiltrations: CanaryHit[];
  skipped?: string;
}

export interface TestOutcome {
  ran: boolean;
  passed: boolean;
  exitCode: number | null;
  command?: string;
  summary: string;
}

export type FindingCategory =
  | 'secret_leak'
  | 'malicious_egress'
  | 'supply_chain'
  | 'injection'
  | 'auth'
  | 'crypto'
  | 'data_exposure'
  | 'insecure_config'
  | 'other';

export interface Finding {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  evidence: string;
  exploitability: string;
  runtimeProof: string;
  remediation: string;
  source: 'static' | 'runtime' | 'ai';
}

export interface EgressVerdict {
  domain: string;
  verdict: 'expected' | 'suspicious' | 'malicious';
  reason: string;
}

export interface PastIncident {
  scanId: string;
  prNumber: number;
  title: string;
  category: string;
  severity: Severity;
  filePath: string;
  description: string;
  similarity: number;
  createdAt: string;
}

export interface AuditResult {
  summary: string;
  riskScore: number;
  severity: SeverityBadge;
  computedRiskScore: number;
  aiRiskScore: number | null;
  findings: Finding[];
  egressAssessment: EgressVerdict[];
  patchRecommended: boolean;
  model: string;
  usedAi: boolean;
}

export interface PatchFile {
  path: string;
  action: 'modify' | 'create' | 'delete';
  /** New UTF-8 content for modify/create. Derived only from trusted inputs (GitHub API + model output). */
  content?: string;
  originalSha256?: string;
  newSha256?: string;
}

export interface PatchVerification {
  status: 'verified' | 'verified_with_warnings' | 'failed';
  testsBefore: TestOutcome;
  testsAfter: TestOutcome;
  remainingLeaks: SecretLeak[];
  resolvedFingerprints: string[];
  unresolvedFingerprints: string[];
  flaggedEgressAfter: string[];
  notes: string[];
  verifiedAt: string;
}

export interface ProposedPatch {
  summary: string;
  files: PatchFile[];
  diff: string;
  diffSha256: string;
  postMergeActions: string[];
  generator: 'claude' | 'heuristic';
  verification: PatchVerification | null;
}

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'awaiting_approval'
  | 'needs_review'
  | 'clean'
  | 'approved'
  | 'pushed'
  | 'publish_failed'
  | 'failed'
  | 'superseded'
  | 'closed';

export type SpriteState = 'none' | 'creating' | 'running' | 'sleeping' | 'destroyed';

export type PatchStatus = 'verified' | 'verified_with_warnings' | 'failed' | 'approved' | 'pushed' | 'publish_failed';

export interface ScanReport {
  scanId: string;
  repoFullName: string;
  prNumber: number;
  prTitle: string;
  headSha: string;
  generatedAt: string;
  audit: AuditResult;
  staticLeaks: SecretLeak[];
  egress: EgressReport;
  pastIncidents: PastIncident[];
  patch: Omit<ProposedPatch, 'files'> & { files: Array<Omit<PatchFile, 'content'>> } | null;
  timings: Record<string, number>;
  sandbox: { driver: string; spriteName: string };
}

export interface ScanRecord {
  id: string;
  repoFullName: string;
  prNumber: number;
  headSha: string;
  headRef: string;
  headRepoFullName: string;
  baseRef: string;
  prTitle: string;
  prAuthor: string;
  status: ScanStatus;
  riskScore: number | null;
  severity: SeverityBadge | null;
  findingsCount: number;
  secretsCount: number;
  flaggedEgressCount: number;
  egressDomains: EgressDomain[];
  spriteName: string | null;
  spriteState: SpriteState;
  checkpointId: string | null;
  reportMarkdown: string | null;
  report: ScanReport | null;
  commentId: number | null;
  error: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface NewScanInput {
  repoFullName: string;
  prNumber: number;
  headSha: string;
  headRef: string;
  headRepoFullName: string;
  baseRef: string;
  prTitle: string;
  prAuthor: string;
}

export interface PatchRecord {
  scanId: string;
  summary: string;
  files: PatchFile[];
  diff: string;
  diffSha256: string;
  verification: PatchVerification | null;
  postMergeActions: string[];
  generator: 'claude' | 'heuristic';
  status: PatchStatus;
  approvedBy: string | null;
  commitSha: string | null;
  createdAt: string;
  approvedAt: string | null;
  pushedAt: string | null;
}

export interface StoredFinding {
  scanId: string;
  repoFullName: string;
  prNumber: number;
  finding: Finding;
  fingerprint: string;
  embedding: number[];
}

export interface DashboardStats {
  prsAudited: number;
  secretsBlocked: number;
  averageRiskScore: number;
  activeSprites: number;
  sleepingSprites: number;
  patchesPushed: number;
  awaitingApproval: number;
}

export interface PrContext {
  owner: string;
  repo: string;
  repoFullName: string;
  number: number;
  title: string;
  body: string;
  author: string;
  headSha: string;
  headRef: string;
  headRepoFullName: string;
  headCloneUrl: string;
  baseRef: string;
  isFork: boolean;
  isPrivate: boolean;
  maintainerCanModify: boolean;
  state: 'open' | 'closed';
}

export interface CommitPatch {
  sha: string;
  message: string;
  author: string;
  files: Array<{ filename: string; patch: string }>;
}
