import { z } from 'zod';

/**
 * Centralised, validated runtime configuration.
 *
 * Every environment variable SpriteGuard reads is declared here. Production mode
 * (LOCAL_SANDBOX_MODE=false) enforces that all credentials for the zero-trust
 * pipeline are present; local sandbox mode relaxes these so the full audit →
 * patch → approval → dashboard loop can be exercised on a laptop.
 */

const bool = (def: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => {
      if (v === undefined || v.trim() === '') return def;
      return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
    });

const int = (def: number, min = 0, max = Number.MAX_SAFE_INTEGER) =>
  z
    .string()
    .optional()
    .transform((v, ctx) => {
      if (v === undefined || v.trim() === '') return def;
      const n = Number.parseInt(v, 10);
      if (!Number.isFinite(n) || n < min || n > max) {
        ctx.addIssue({ code: 'custom', message: `must be an integer in [${min}, ${max}]` });
        return z.NEVER;
      }
      return n;
    });

const optionalString = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? undefined : v.trim()));

const optionalUrl = z
  .string()
  .optional()
  .transform((v, ctx) => {
    if (v === undefined || v.trim() === '') return undefined;
    const trimmed = v.trim();
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        ctx.addIssue({ code: 'custom', message: 'must use http:// or https://' });
        return z.NEVER;
      }
      return trimmed.replace(/\/+$/, '');
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be a valid http(s) URL' });
      return z.NEVER;
    }
  });

const csv = (def: string[]) =>
  z
    .string()
    .optional()
    .transform((v) =>
      v === undefined || v.trim() === ''
        ? def
        : v
            .split(',')
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean),
    );

export const DEFAULT_EGRESS_ALLOWLIST = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'pypi.org',
  'files.pythonhosted.org',
  'github.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  'nodejs.org',
];

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: int(8080, 1, 65535),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  PUBLIC_URL: optionalString,

  LOCAL_SANDBOX_MODE: bool(false),
  LOCAL_ALLOW_UNTRUSTED_EXEC: bool(false),

  ANTHROPIC_API_KEY: optionalString,
  ANTHROPIC_MODEL: z.string().default('claude-opus-4-6'),
  ANTHROPIC_MAX_TOKENS: int(8192, 1024, 64000),

  LLM_BASE_URL: optionalUrl,
  LLM_API_KEY: optionalString,
  LLM_MODEL: optionalString,

  DATABASE_URL: optionalString,
  DATABASE_SSL: optionalString,
  VOYAGE_API_KEY: optionalString,
  VOYAGE_MODEL: z.string().default('voyage-3.5-lite'),

  GITHUB_WEBHOOK_SECRET: optionalString,
  GITHUB_API_URL: z.string().url().default('https://api.github.com'),
  GITHUB_APP_ID: optionalString,
  GITHUB_APP_PRIVATE_KEY: optionalString,
  GITHUB_READ_TOKEN: optionalString,
  GITHUB_WRITE_TOKEN: optionalString,
  GITHUB_BOT_LOGIN: z.string().default('spriteguard[bot]'),
  APPROVER_MIN_PERMISSION: z.enum(['admin', 'maintain', 'write']).default('maintain'),

  SPRITES_TOKEN: optionalString,
  FLY_API_TOKEN: optionalString,
  SPRITES_API_URL: z.string().url().default('https://api.sprites.dev'),
  SPRITE_NAME_PREFIX: z.string().regex(/^[a-z][a-z0-9-]{0,15}$/).default('sg'),
  SPRITE_TTL_HOURS: int(72, 1, 24 * 30),
  SPRITE_EGRESS_ALLOWLIST: csv(DEFAULT_EGRESS_ALLOWLIST),
  SPRITE_ENFORCE_EGRESS_POLICY: bool(true),

  AUDIT_INSTALL_TIMEOUT_SEC: int(600, 10, 3600),
  AUDIT_TEST_TIMEOUT_SEC: int(600, 10, 3600),
  MAX_CONCURRENT_AUDITS: int(2, 1, 32),
  MAX_DIFF_CHARS: int(120_000, 5_000, 1_000_000),
  AUTO_PATCH: bool(true),
  DASHBOARD_TOKEN: optionalString,
});

export type ApproverPermission = 'admin' | 'maintain' | 'write';
export type LlmProviderKind = 'openai-compatible' | 'anthropic' | 'heuristic';

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  host: string;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';
  publicUrl: string | undefined;
  localSandboxMode: boolean;
  localAllowUntrustedExec: boolean;
  anthropic: { apiKey: string | undefined; model: string; maxTokens: number };
  llm: {
    provider: LlmProviderKind;
    baseUrl: string | undefined;
    apiKey: string | undefined;
    model: string;
    maxTokens: number;
  };
  database: { url: string | undefined; ssl: boolean };
  embeddings: { voyageApiKey: string | undefined; voyageModel: string; dimensions: number };
  github: {
    webhookSecret: string;
    apiUrl: string;
    appId: string | undefined;
    appPrivateKey: string | undefined;
    readToken: string | undefined;
    writeToken: string | undefined;
    botLogin: string;
    approverMinPermission: ApproverPermission;
  };
  sprites: {
    token: string | undefined;
    apiUrl: string;
    namePrefix: string;
    ttlHours: number;
    egressAllowlist: string[];
    enforceEgressPolicy: boolean;
  };
  audit: {
    installTimeoutSec: number;
    testTimeoutSec: number;
    maxConcurrent: number;
    maxDiffChars: number;
    autoPatch: boolean;
  };
  dashboardToken: string | undefined;
}

export const LOCAL_DEV_WEBHOOK_SECRET = 'spriteguard-local-dev-secret';

function decodePrivateKey(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  if (raw.includes('-----BEGIN')) return raw.replace(/\\n/g, '\n');
  try {
    const decoded = Buffer.from(raw, 'base64').toString('utf8');
    return decoded.includes('-----BEGIN') ? decoded : raw;
  } catch {
    return raw;
  }
}

function shouldUseSsl(url: string | undefined, flag: string | undefined): boolean {
  if (flag !== undefined) return ['1', 'true', 'yes', 'require', 'on'].includes(flag.toLowerCase());
  if (!url) return false;
  return !/@(localhost|127\.0\.0\.1|\[::1\])(:\d+)?\//.test(url);
}

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  • ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid SpriteGuard configuration:\n${issues}`);
  }
  const e = parsed.data;
  const local = e.LOCAL_SANDBOX_MODE;
  const spritesToken = e.SPRITES_TOKEN ?? e.FLY_API_TOKEN;
  const appPrivateKey = decodePrivateKey(e.GITHUB_APP_PRIVATE_KEY);

  if (!local) {
    const missing: string[] = [];
    if (!e.LLM_BASE_URL && !e.ANTHROPIC_API_KEY) missing.push('ANTHROPIC_API_KEY (or LLM_BASE_URL)');
    if (!e.DATABASE_URL) missing.push('DATABASE_URL');
    if (!e.GITHUB_WEBHOOK_SECRET) missing.push('GITHUB_WEBHOOK_SECRET');
    if (!spritesToken) missing.push('SPRITES_TOKEN (or FLY_API_TOKEN)');
    const hasApp = Boolean(e.GITHUB_APP_ID && appPrivateKey);
    const hasTokens = Boolean(e.GITHUB_READ_TOKEN && e.GITHUB_WRITE_TOKEN);
    if (!hasApp && !hasTokens) {
      missing.push('GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY (or GITHUB_READ_TOKEN + GITHUB_WRITE_TOKEN)');
    }
    if (missing.length > 0) {
      throw new Error(
        `SpriteGuard is running in production mode (LOCAL_SANDBOX_MODE=false) but these variables are missing:\n` +
          missing.map((m) => `  • ${m}`).join('\n') +
          `\nSet LOCAL_SANDBOX_MODE=true to run the local demo instead.`,
      );
    }
    if (e.GITHUB_READ_TOKEN && e.GITHUB_WRITE_TOKEN && e.GITHUB_READ_TOKEN === e.GITHUB_WRITE_TOKEN) {
      throw new Error(
        'GITHUB_READ_TOKEN and GITHUB_WRITE_TOKEN must be different credentials: the split-connector model requires a read-only token for audits.',
      );
    }
  }

  const llm: AppConfig['llm'] = e.LLM_BASE_URL
    ? {
        provider: 'openai-compatible',
        baseUrl: e.LLM_BASE_URL,
        apiKey: e.LLM_API_KEY,
        model: e.LLM_MODEL ?? 'gpt-4o',
        maxTokens: e.ANTHROPIC_MAX_TOKENS,
      }
    : e.ANTHROPIC_API_KEY
      ? {
          provider: 'anthropic',
          baseUrl: undefined,
          apiKey: e.ANTHROPIC_API_KEY,
          model: e.ANTHROPIC_MODEL,
          maxTokens: e.ANTHROPIC_MAX_TOKENS,
        }
      : {
          provider: 'heuristic',
          baseUrl: undefined,
          apiKey: undefined,
          model: e.LLM_MODEL ?? e.ANTHROPIC_MODEL,
          maxTokens: e.ANTHROPIC_MAX_TOKENS,
        };

  return {
    env: e.NODE_ENV,
    port: e.PORT,
    host: e.HOST,
    logLevel: e.LOG_LEVEL,
    publicUrl: e.PUBLIC_URL?.replace(/\/+$/, ''),
    localSandboxMode: local,
    localAllowUntrustedExec: e.LOCAL_ALLOW_UNTRUSTED_EXEC,
    anthropic: { apiKey: e.ANTHROPIC_API_KEY, model: e.ANTHROPIC_MODEL, maxTokens: e.ANTHROPIC_MAX_TOKENS },
    llm,
    database: { url: e.DATABASE_URL, ssl: shouldUseSsl(e.DATABASE_URL, e.DATABASE_SSL) },
    embeddings: { voyageApiKey: e.VOYAGE_API_KEY, voyageModel: e.VOYAGE_MODEL, dimensions: 1024 },
    github: {
      webhookSecret: e.GITHUB_WEBHOOK_SECRET ?? LOCAL_DEV_WEBHOOK_SECRET,
      apiUrl: e.GITHUB_API_URL.replace(/\/+$/, ''),
      appId: e.GITHUB_APP_ID,
      appPrivateKey,
      readToken: e.GITHUB_READ_TOKEN,
      writeToken: e.GITHUB_WRITE_TOKEN,
      botLogin: e.GITHUB_BOT_LOGIN,
      approverMinPermission: e.APPROVER_MIN_PERMISSION,
    },
    sprites: {
      token: spritesToken,
      apiUrl: e.SPRITES_API_URL.replace(/\/+$/, ''),
      namePrefix: e.SPRITE_NAME_PREFIX,
      ttlHours: e.SPRITE_TTL_HOURS,
      egressAllowlist: e.SPRITE_EGRESS_ALLOWLIST,
      enforceEgressPolicy: e.SPRITE_ENFORCE_EGRESS_POLICY,
    },
    audit: {
      installTimeoutSec: e.AUDIT_INSTALL_TIMEOUT_SEC,
      testTimeoutSec: e.AUDIT_TEST_TIMEOUT_SEC,
      maxConcurrent: e.MAX_CONCURRENT_AUDITS,
      maxDiffChars: e.MAX_DIFF_CHARS,
      autoPatch: e.AUTO_PATCH,
    },
    dashboardToken: e.DASHBOARD_TOKEN,
  };
}
