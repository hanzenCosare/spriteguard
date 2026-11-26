import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ReadOnlyGitHubConnector } from '../fly/githubConnector.js';
import type { Logger } from '../logger.js';
import type { AuditOrchestrator } from '../orchestrator.js';

/**
 * GitHub Webhook signature verification & event routing.
 */

export function verifyWebhookSignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=') || !secret) return false;
  const sigHex = signatureHeader.slice(7).trim();
  if (!/^[a-f0-9]{64}$/i.test(sigHex)) return false;

  const expected = createHmac('sha256', secret).update(rawBody).digest();
  const actual = Buffer.from(sigHex, 'hex');
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

export type CommentCommand =
  | { kind: 'approve' }
  | { kind: 'rescan' }
  | { kind: 'ask'; question: string };

export function parseCommentCommand(body: string): CommentCommand | null {
  if (!body) return null;

  // Strip fenced code blocks and inline backtick spans so instructions don't look like commands
  const stripped = body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]*`/g, ' ');

  for (const rawLine of stripped.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    if (/^\/spriteguard\s+approve(?:\s+.*)?$/i.test(line)) {
      return { kind: 'approve' };
    }
    if (/^\/spriteguard\s+(?:rescan|audit)(?:\s+.*)?$/i.test(line)) {
      return { kind: 'rescan' };
    }
  }

  const mention = /(?:^|\s)@spriteguard\b([\s\S]*)/i.exec(stripped);
  if (mention) {
    const question = (mention[1] ?? '').replace(/^[:,.\s-]+/, '').trim();
    if (question.length > 0) {
      return { kind: 'ask', question };
    }
  }

  return null;
}

export interface WebhookResult {
  statusCode: number;
  accepted: boolean;
  action: string;
  detail?: string;
}

interface WebhookPayload {
  action?: string;
  installation?: { id?: number };
  repository?: { full_name?: string };
  sender?: { login?: string; type?: string };
  pull_request?: {
    number?: number;
    state?: string;
    head?: { sha?: string };
  };
  issue?: {
    number?: number;
    pull_request?: unknown;
  };
  comment?: {
    id?: number;
    body?: string;
    user?: { login?: string; type?: string };
  };
  zen?: string;
}

export class WebhookHandler {
  private readonly seenDeliveries = new Set<string>();

  constructor(
    private readonly webhookSecret: string,
    private readonly botLogin: string,
    private readonly readConnector: ReadOnlyGitHubConnector,
    private readonly orchestrator: AuditOrchestrator,
    private readonly log: Logger,
  ) {}

  private rememberDelivery(deliveryId: string | undefined): boolean {
    if (!deliveryId) return true;
    if (this.seenDeliveries.has(deliveryId)) return false;
    this.seenDeliveries.add(deliveryId);
    if (this.seenDeliveries.size > 2000) {
      const first = this.seenDeliveries.values().next().value;
      if (first) this.seenDeliveries.delete(first);
    }
    return true;
  }

  async handle(params: {
    event: string | undefined;
    deliveryId: string | undefined;
    signature256: string | undefined;
    rawBody: Buffer;
    payload: unknown;
  }): Promise<WebhookResult> {
    if (!verifyWebhookSignature(params.rawBody, params.signature256, this.webhookSecret)) {
      return { statusCode: 401, accepted: false, action: 'rejected', detail: 'Invalid X-Hub-Signature-256' };
    }

    if (!this.rememberDelivery(params.deliveryId)) {
      return { statusCode: 200, accepted: true, action: 'duplicate_delivery' };
    }

    const body = (params.payload ?? {}) as WebhookPayload;
    const repoFullName = body.repository?.full_name;
    const installationId = body.installation?.id;

    if (repoFullName && typeof installationId === 'number') {
      this.readConnector.rememberInstallation(repoFullName, installationId);
      this.orchestrator.publisher.rememberInstallation(repoFullName, installationId);
    }

    if (params.event === 'ping') {
      return { statusCode: 200, accepted: true, action: 'pong', detail: body.zen };
    }

    if (params.event === 'pull_request') {
      const prNumber = body.pull_request?.number;
      if (!repoFullName || !prNumber) {
        return { statusCode: 400, accepted: false, action: 'ignored', detail: 'Missing repository or pull_request.number' };
      }

      if (body.action === 'opened' || body.action === 'synchronize' || body.action === 'reopened') {
        const queued = this.orchestrator.enqueuePullRequestAudit(repoFullName, prNumber);
        return {
          statusCode: 202,
          accepted: queued.accepted,
          action: queued.accepted ? 'audit_queued' : 'audit_already_inflight',
          detail: `${repoFullName}#${prNumber}`,
        };
      }

      if (body.action === 'closed') {
        void this.orchestrator.handlePullRequestClosed(repoFullName, prNumber).catch((err) => {
          this.log.warn({ err, repoFullName, prNumber }, 'failed to clean up sprites on PR close');
        });
        return { statusCode: 200, accepted: true, action: 'pr_closed_cleanup', detail: `${repoFullName}#${prNumber}` };
      }

      return { statusCode: 200, accepted: true, action: `ignored_pr_action:${body.action ?? 'unknown'}` };
    }

    if (params.event === 'issue_comment') {
      if (body.action !== 'created') {
        return { statusCode: 200, accepted: true, action: `ignored_comment_action:${body.action ?? 'unknown'}` };
      }
      if (!body.issue?.pull_request || !repoFullName || !body.issue.number) {
        return { statusCode: 200, accepted: true, action: 'ignored_non_pr_comment' };
      }

      const commenter = body.comment?.user?.login ?? body.sender?.login ?? '';
      const commenterType = body.comment?.user?.type ?? body.sender?.type ?? '';
      if (
        !commenter ||
        commenter.toLowerCase() === this.botLogin.toLowerCase() ||
        commenterType === 'Bot' ||
        (body.comment?.body ?? '').includes('<!-- spriteguard-audit:')
      ) {
        return { statusCode: 200, accepted: true, action: 'ignored_bot_comment' };
      }

      const cmd = parseCommentCommand(body.comment?.body ?? '');
      if (!cmd) {
        return { statusCode: 200, accepted: true, action: 'ignored_plain_comment' };
      }

      const prNumber = body.issue.number;
      const commentId = body.comment?.id;

      if (cmd.kind === 'approve') {
        void this.orchestrator.handleApproval(repoFullName, prNumber, commenter, commentId).catch((err) => {
          this.log.error({ err, repoFullName, prNumber, commenter }, 'approval execution failed');
        });
        return { statusCode: 202, accepted: true, action: 'approval_queued', detail: `${repoFullName}#${prNumber}` };
      }

      if (cmd.kind === 'rescan') {
        const queued = this.orchestrator.enqueuePullRequestAudit(repoFullName, prNumber);
        return { statusCode: 202, accepted: queued.accepted, action: 'rescan_queued', detail: `${repoFullName}#${prNumber}` };
      }

      if (cmd.kind === 'ask') {
        void this.orchestrator
          .handleQuestion(repoFullName, prNumber, commenter, cmd.question, commentId)
          .catch((err) => {
            this.log.error({ err, repoFullName, prNumber, commenter }, 'Q&A reply failed');
          });
        return { statusCode: 202, accepted: true, action: 'qa_queued', detail: `${repoFullName}#${prNumber}` };
      }
    }

    return { statusCode: 200, accepted: true, action: `ignored_event:${params.event ?? 'unknown'}` };
  }
}
