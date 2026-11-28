/**
 * Contracts for the zero-dependency deterministic fallback Q&A engine.
 */

export type DeterministicSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface DeterministicFinding {
  id: string;
  title: string;
  severity: DeterministicSeverity;
  category: string;
  file: string;
  line: number;
  redactedSecret?: string | null;
  entropy?: number | null;
  fingerprint?: string | null;
  evidence?: string | null;
  exploitability?: string | null;
  runtimeProof?: string | null;
  remediation?: string | null;
  confidence?: number | null;
  source?: string | null;
  riskContribution?: number | null;
  commitSha?: string | null;
  isHistoryLeak?: boolean;
}

export interface DeterministicEgressEvent {
  domain: string;
  port?: number | null;
  phase: string;
  hitCount: number;
  sampleUrls?: string[];
  flagged: boolean;
  reasons?: string[];
  associatedFindingId?: string | null;
}

export interface DeterministicCanaryHit {
  canary: string;
  channel: string;
  detail: string;
}

export interface DeterministicPatch {
  status: string;
  summary?: string | null;
  diff?: string | null;
  validationStatus?: string | null;
  testStatus?: string | null;
  testSummary?: string | null;
  testOutput?: string | null;
  resolvedLeaks?: number;
  remainingLeaks?: number;
  flaggedEgressAfterPatch?: number;
  pushed?: boolean;
  commitSha?: string | null;
  generator?: string | null;
  postMergeActions?: string[];
  notes?: string[];
}

export interface DeterministicSprite {
  id?: string | null;
  lifecycle?: string | null;
  checkpoint?: string | null;
  durationMs?: number | null;
  runtimeEnv?: string | null;
  isolationSandbox?: string | null;
}

export interface DeterministicRiskContributions {
  secrets?: number;
  egress?: number;
  code?: number;
  breakdown?: Array<{ label: string; points: number }>;
}

export interface DeterministicRelatedIncident {
  prNumber: number;
  title: string;
  similarity: number;
}

export interface DeterministicAuditPayload {
  repo: string;
  prNumber: number;
  prTitle?: string | null;
  commitSha: string;
  branch?: string | null;
  riskScore: number;
  severity: string;
  status: string;
  riskContributions?: DeterministicRiskContributions | null;
  findings: DeterministicFinding[];
  egressEvents: DeterministicEgressEvent[];
  canaryHits?: DeterministicCanaryHit[];
  patch?: DeterministicPatch | null;
  sprite?: DeterministicSprite | null;
  relatedIncidents?: DeterministicRelatedIncident[];
}

export type IntentId =
  | 'secrets'
  | 'location'
  | 'egress'
  | 'fix'
  | 'exploit'
  | 'approve'
  | 'diff'
  | 'evidence'
  | 'metadata'
  | 'false_positive'
  | 'next_steps'
  | 'draft'
  | 'quantitative'
  | 'boolean'
  | 'comparison'
  | 'full_report'
  | 'summary';

export type TurnOutcomeKind =
  | IntentId
  | 'compound'
  | 'disambiguation'
  | 'out_of_scope'
  | 'clean_short_circuit';

export const DETERMINISTIC_BADGE = 'Answered by deterministic fallback' as const;

export interface ConversationTurnMeta {
  entityType: 'finding' | 'file' | 'domain' | 'patch' | 'audit' | 'none';
  findingIds: string[];
  files: string[];
  domains: string[];
  lastIntent: TurnOutcomeKind;
  suggestedQuestions: string[];
  badge: typeof DETERMINISTIC_BADGE;
}

export interface ConversationTurn {
  role: 'user' | 'assistant';
  content: string;
  meta?: Partial<ConversationTurnMeta>;
}

export interface NormalizedQuery {
  raw: string;
  cleaned: string;
  lower: string;
  tokens: string[];
  stemmedTokens: string[];
  identifierTokens: string[];
  hasCompoundJoiner: boolean;
  isShortVague: boolean;
  isPromptInjection: boolean;
}

export interface EntityResolution {
  matchedFindings: DeterministicFinding[];
  matchedFiles: string[];
  matchedDomains: DeterministicEgressEvent[];
  absentDomains: string[];
  requestedLine?: number | null;
  requestedFailingTest: boolean;
  matchStrength: 'exact' | 'fuzzy' | 'none';
  isEntityScoped: boolean;
  resolvedFromMemory: boolean;
  requestedCategory?: 'secret' | 'egress' | 'code' | null;
}

export interface ScoredIntent {
  intent: IntentId;
  score: number;
  reasons: string[];
}

export interface DeterministicQaResponse {
  answer: string;
  badge: typeof DETERMINISTIC_BADGE;
  meta: ConversationTurnMeta;
  isOutOfScope: boolean;
  winningIntents: IntentId[];
  latencyMs: number;
}
