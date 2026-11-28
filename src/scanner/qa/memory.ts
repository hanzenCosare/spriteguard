import { sortFindingsByPriority } from './entities.js';
import type {
  ConversationTurn,
  DeterministicAuditPayload,
  DeterministicEgressEvent,
  DeterministicFinding,
  EntityResolution,
  NormalizedQuery,
} from './types.js';

/**
 * Stage 2 — Single-turn conversational thread memory & pronoun/demonstrative resolver.
 */

const PRONOUN_PATTERN =
  /\b(?:it|that|this|them|those|this\s+one|that\s+one|same\s+one)\b/i;

const OTHER_ONE_PATTERN =
  /\b(?:the\s+)?other(?:\s+(?:one|finding|issue|file|domain|secret|leak))?\b/i;

const ORDINAL_FOLLOWUP_PATTERN =
  /\b(?:the\s+)?(first|second|third|fourth)\s+one\b/i;

interface ExtractedTurnEntities {
  findingIds: string[];
  files: string[];
  domains: string[];
}

export function extractEntitiesFromTurn(
  turn: ConversationTurn,
  audit: DeterministicAuditPayload,
): ExtractedTurnEntities {
  const findingIds = new Set<string>(turn.meta?.findingIds ?? []);
  const files = new Set<string>(turn.meta?.files ?? []);
  const domains = new Set<string>(turn.meta?.domains ?? []);

  // Fallback text extraction if caller only provided plain { role, content }
  if (findingIds.size === 0 && files.size === 0 && domains.size === 0 && turn.content) {
    const low = turn.content.toLowerCase();
    for (const f of audit.findings ?? []) {
      const base = f.file.split('/').pop()?.toLowerCase() ?? '';
      if (
        (f.title && low.includes(f.title.toLowerCase())) ||
        (f.file && low.includes(f.file.toLowerCase())) ||
        (base.length >= 4 && low.includes(base)) ||
        (f.redactedSecret && low.includes(f.redactedSecret.toLowerCase()))
      ) {
        findingIds.add(f.id);
        if (f.file) files.add(f.file);
      }
    }
    for (const ev of audit.egressEvents ?? []) {
      if (ev.domain && low.includes(ev.domain.toLowerCase())) {
        domains.add(ev.domain.toLowerCase());
      }
    }
  }

  return {
    findingIds: [...findingIds],
    files: [...files],
    domains: [...domains],
  };
}

function findLastAssistantTurn(history: readonly ConversationTurn[]): ConversationTurn | null {
  for (let i = history.length - 1; i >= 0; i--) {
    const t = history[i];
    if (t && t.role === 'assistant') return t;
  }
  return null;
}

export function resolveConversationalContext(
  nq: NormalizedQuery,
  audit: DeterministicAuditPayload,
  history: readonly ConversationTurn[],
  currentEntities: EntityResolution,
): EntityResolution {
  // If user already named an explicit entity in this turn, prefer the explicit entity
  if (currentEntities.isEntityScoped) return currentEntities;
  if (!history || history.length === 0) return currentEntities;

  const prevAssistant = findLastAssistantTurn(history);
  if (!prevAssistant) return currentEntities;

  const sortedFindings = sortFindingsByPriority(audit.findings ?? []);
  const prevEntities = extractEntitiesFromTurn(prevAssistant, audit);

  // 1. Handle "what about the other one?" -> complement of Turn N-1 findings
  if (OTHER_ONE_PATTERN.test(nq.raw) && sortedFindings.length > 1) {
    const prevSet = new Set(prevEntities.findingIds);
    const remaining: DeterministicFinding[] =
      prevSet.size > 0 && prevSet.size < sortedFindings.length
        ? sortedFindings.filter((f) => !prevSet.has(f.id))
        : sortedFindings.slice(1);

    if (remaining.length > 0) {
      const remFiles = [...new Set(remaining.map((f) => f.file).filter(Boolean))];
      const remDomains = (audit.egressEvents ?? []).filter((ev) =>
        remaining.some((f) => ev.associatedFindingId === f.id || `${f.title} ${f.evidence ?? ''}`.toLowerCase().includes(ev.domain.toLowerCase())),
      );
      return {
        ...currentEntities,
        matchedFindings: remaining,
        matchedFiles: remFiles,
        matchedDomains: remDomains,
        matchStrength: 'exact',
        isEntityScoped: true,
        resolvedFromMemory: true,
      };
    }
  }

  // 2. Handle ordinal follow-up ("the first one", "the second one")
  const ordMatch = ORDINAL_FOLLOWUP_PATTERN.exec(nq.raw);
  if (ordMatch?.[1]) {
    const map: Record<string, number> = { first: 0, second: 1, third: 2, fourth: 3 };
    const idx = map[ordMatch[1].toLowerCase()] ?? 0;
    const pool =
      prevEntities.findingIds.length > 1
        ? sortedFindings.filter((f) => prevEntities.findingIds.includes(f.id))
        : sortedFindings;
    const picked = pool[idx];
    if (picked) {
      return {
        ...currentEntities,
        matchedFindings: [picked],
        matchedFiles: picked.file ? [picked.file] : [],
        matchedDomains: (audit.egressEvents ?? []).filter((ev) => ev.associatedFindingId === picked.id),
        matchStrength: 'exact',
        isEntityScoped: true,
        resolvedFromMemory: true,
      };
    }
  }

  // 3. Handle pronouns & demonstratives ("how do I fix that?", "where is it?", "why is that risky?", "show me the diff for it")
  if (PRONOUN_PATTERN.test(nq.raw)) {
    const prevFindings = sortedFindings.filter((f) => prevEntities.findingIds.includes(f.id));
    const prevDomains: DeterministicEgressEvent[] = (audit.egressEvents ?? []).filter((ev) =>
      prevEntities.domains.includes(ev.domain.toLowerCase()),
    );
    const prevFiles = prevEntities.files;

    if (prevFindings.length > 0 || prevFiles.length > 0 || prevDomains.length > 0) {
      return {
        ...currentEntities,
        matchedFindings: prevFindings,
        matchedFiles: prevFiles,
        matchedDomains: prevDomains,
        matchStrength: 'exact',
        isEntityScoped: true,
        resolvedFromMemory: true,
      };
    }
  }

  return currentEntities;
}
