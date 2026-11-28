import { stripAnsi } from './normalize.js';
import type { DeterministicFinding } from './types.js';

/**
 * Deep diagnostic & log parsing:
 *  - ANSI-safe test failure root-cause extractor (Jest, Vitest, Node, Mocha, Pytest, Go)
 *  - Unified patch diff hunk extractor & plain-English diff summary synthesizer
 *  - Language-tagged code evidence renderer
 */

export interface ParsedTestFailure {
  exitCode: number | null;
  failingSuite: string | null;
  primaryError: string | null;
  truncated: boolean;
}

export interface FileDiffSummary {
  file: string;
  added: number;
  removed: number;
  description: string;
  rawHunk: string;
}

const SUITE_PATTERNS: readonly RegExp[] = [
  /^\s*FAIL\s+(.+?)\s*$/,
  /^\s*✖\s+(.+?)\s*$/,
  /^\s*not\s+ok\s+\d+\s*-?\s*(.+?)\s*$/,
  /^\s*FAILED\s+([^\s]+(?:::[^\s]+)?)/,
  /^\s*---\s*FAIL:\s+(.+?)\s*$/,
  /^\s*test\s+at\s+(.+?)\s*$/,
  /^\s*\d+\)\s+(.+?)\s*$/,
];

const ERROR_LINE_PATTERNS: readonly RegExp[] = [
  /\b(?:TypeError|ReferenceError|SyntaxError|RangeError|URIError|AssertionError|Error)\b[:\s].+/,
  /\bERR_ASSERTION\b.+/,
  /\bCannot find module\b.+/,
  /\bExpected\b.*(?:Received|to equal|to be|to match).*/i,
  /\bAssertionError\b.*/i,
  /\bE\s+(?:AssertionError|TypeError|ValueError|KeyError|AttributeError|ImportError|ModuleNotFoundError|RuntimeError)[:\s].*/,
];

function truncateText(text: string, maxLen = 200): { text: string; truncated: boolean } {
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= maxLen) return { text: clean, truncated: false };
  return { text: `${clean.slice(0, maxLen - 1).trimEnd()}…`, truncated: true };
}

export function parseTestFailure(rawOutput?: string | null): ParsedTestFailure | null {
  if (!rawOutput || !rawOutput.trim()) return null;
  const clean = stripAnsi(rawOutput);
  const lines = clean.split(/\r?\n/);

  let exitCode: number | null = null;
  const exitMatch =
    /(?:command\s+exited\s+with\s+code|exit(?:ed)?\s+(?:with\s+)?code|exit\s+status|status\s+code)\s*[:=]?\s*(\d+)/i.exec(
      clean,
    );
  if (exitMatch?.[1]) {
    const parsed = Number.parseInt(exitMatch[1], 10);
    if (Number.isFinite(parsed)) exitCode = parsed;
  }

  let failingSuite: string | null = null;
  for (const line of lines) {
    for (const pat of SUITE_PATTERNS) {
      const m = pat.exec(line);
      if (m?.[1]) {
        failingSuite = m[1].trim().slice(0, 140);
        break;
      }
    }
    if (failingSuite) break;
  }

  let rawErrorLine: string | null = null;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    for (const pat of ERROR_LINE_PATTERNS) {
      if (pat.test(trimmed)) {
        rawErrorLine = trimmed;
        break;
      }
    }
    if (rawErrorLine) break;
  }

  // Fallback for Python Tracebacks: take the last non-empty error line after Traceback
  if (!rawErrorLine && /Traceback \(most recent call last\)/i.test(clean)) {
    for (let i = lines.length - 1; i >= 0; i--) {
      const t = (lines[i] ?? '').trim();
      if (t && /^[A-Za-z_]\w*(?:Error|Exception)\b/.test(t)) {
        rawErrorLine = t;
        break;
      }
    }
  }

  // Fallback: Expected / Received pair on adjacent lines
  if (!rawErrorLine) {
    const expIdx = lines.findIndex((l) => /^\s*Expected:/i.test(l));
    if (expIdx >= 0) {
      const exp = (lines[expIdx] ?? '').trim();
      const rec = (lines[expIdx + 1] ?? '').trim();
      rawErrorLine = /Received:/i.test(rec) ? `${exp} | ${rec}` : exp;
    }
  }

  const truncatedRes = rawErrorLine ? truncateText(rawErrorLine, 200) : null;
  const outputLooksTruncated =
    Boolean(truncatedRes?.truncated) || clean.length >= 3500 || /\.\.\.\s*truncated/i.test(clean);

  return {
    exitCode,
    failingSuite,
    primaryError: truncatedRes ? truncatedRes.text : null,
    truncated: outputLooksTruncated,
  };
}

export function extractFileDiffHunks(diff?: string | null, targetFiles?: readonly string[]): FileDiffSummary[] {
  if (!diff || !diff.trim()) return [];
  const lines = diff.split(/\r?\n/);
  const sections: Array<{ file: string; lines: string[] }> = [];
  let current: { file: string; lines: string[] } | null = null;

  for (const line of lines) {
    const gitMatch = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
    if (gitMatch?.[2]) {
      current = { file: gitMatch[2].trim(), lines: [line] };
      sections.push(current);
      continue;
    }
    if (!current) {
      const plusMatch = /^\+\+\+ b\/(.+)$/.exec(line);
      const minusMatch = /^--- a\/(.+)$/.exec(line);
      if (minusMatch?.[1] && minusMatch[1] !== '/dev/null') {
        current = { file: minusMatch[1].trim(), lines: [line] };
        sections.push(current);
        continue;
      }
      if (plusMatch?.[1] && plusMatch[1] !== '/dev/null') {
        current = { file: plusMatch[1].trim(), lines: [line] };
        sections.push(current);
        continue;
      }
    }
    if (current) current.lines.push(line);
  }

  const wantedSet =
    targetFiles && targetFiles.length > 0 ? new Set(targetFiles.map((f) => f.toLowerCase())) : null;

  const filtered = wantedSet
    ? sections.filter((s) => {
        const low = s.file.toLowerCase();
        const base = low.split('/').pop() ?? low;
        return wantedSet.has(low) || wantedSet.has(base);
      })
    : sections;

  return filtered.map((sec) => {
    let added = 0;
    let removed = 0;
    const addedLines: string[] = [];
    const removedLines: string[] = [];

    for (const l of sec.lines) {
      if (l.startsWith('+++') || l.startsWith('---') || l.startsWith('diff --git')) continue;
      if (l.startsWith('+')) {
        added++;
        addedLines.push(l.slice(1));
      } else if (l.startsWith('-')) {
        removed++;
        removedLines.push(l.slice(1));
      }
    }

    const description = synthesizeFileTransformation(sec.file, addedLines, removedLines, added, removed);
    return {
      file: sec.file,
      added,
      removed,
      description,
      rawHunk: sec.lines.join('\n'),
    };
  });
}

function synthesizeFileTransformation(
  file: string,
  addedLines: string[],
  removedLines: string[],
  added: number,
  removed: number,
): string {
  const addedBlob = addedLines.join('\n');
  const removedBlob = removedLines.join('\n');
  const delta = `(+${added} / -${removed} line${added + removed === 1 ? '' : 's'})`;

  if (/^\.env(?:\..+)?$/i.test(file.split('/').pop() ?? file) && added === 0 && removed > 0) {
    return `Deleted tracked environment file \`${file}\` ${delta}`;
  }

  const envVarMatch =
    /process\.env\.([A-Z0-9_]+)/.exec(addedBlob) ??
    /os\.environ(?:\.get)?\(\s*["']([A-Z0-9_]+)["']/.exec(addedBlob) ??
    /os\.Getenv\(\s*["']([A-Z0-9_]+)["']/.exec(addedBlob);

  const removedEgressHost =
    /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i.exec(removedBlob)?.[1] ?? null;

  const actions: string[] = [];
  if (envVarMatch?.[1]) {
    actions.push(`Replaced hardcoded literal with \`${envVarMatch[0]}\``);
  }
  if (removedEgressHost && !addedBlob.includes(removedEgressHost)) {
    actions.push(`Removed unauthorized outbound call to \`${removedEgressHost}\``);
  } else if (/\b(?:fetch|axios|http\.request|https\.request|urllib|requests\.post)\s*\(/i.test(removedBlob) && !/\b(?:fetch|axios|http\.request|https\.request)\s*\(/i.test(addedBlob)) {
    actions.push('Removed unauthorized outbound network call');
  }

  if (actions.length > 0) {
    return `${actions.join(' and ')} in \`${file}\` ${delta}`;
  }

  return `Updated \`${file}\` ${delta}`;
}

export function summarizePatchDiff(diff?: string | null, targetFiles?: readonly string[]): FileDiffSummary[] {
  return extractFileDiffHunks(diff, targetFiles);
}

export function languageForFile(filePath?: string | null): string {
  if (!filePath) return '';
  const base = filePath.split('/').pop()?.toLowerCase() ?? '';
  if (base === 'dockerfile') return 'dockerfile';
  if (base.startsWith('.env')) return 'dotenv';
  const ext = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : '';
  switch (ext) {
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
      return 'javascript';
    case 'ts':
    case 'tsx':
      return 'typescript';
    case 'py':
      return 'python';
    case 'go':
      return 'go';
    case 'rb':
      return 'ruby';
    case 'rs':
      return 'rust';
    case 'java':
      return 'java';
    case 'sh':
    case 'bash':
    case 'zsh':
      return 'bash';
    case 'yml':
    case 'yaml':
      return 'yaml';
    case 'json':
      return 'json';
    case 'toml':
      return 'toml';
    case 'sql':
      return 'sql';
    default:
      return '';
  }
}

export function renderEvidenceBlock(finding: DeterministicFinding): string {
  const loc = finding.line > 0 ? `${finding.file}:${finding.line}` : finding.file;
  if (!finding.evidence || !finding.evidence.trim()) {
    return `Evidence for \`${loc}\`: Not available for this audit run.`;
  }
  const lang = languageForFile(finding.file);
  return [`Code evidence at \`${loc}\`:`, `\`\`\`${lang}`, finding.evidence.trim(), '```'].join('\n');
}
