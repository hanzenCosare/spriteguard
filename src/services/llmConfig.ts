import type { AppConfig, LlmProviderKind } from '../config.js';

export type LlmProviderId = 'local' | 'openrouter' | 'gemini' | 'claude' | 'zero-ai';
export type LlmKeySource = 'env' | 'runtime' | 'none';
export type LlmEngineKind = 'llm' | 'deterministic';
export type LlmHealthStatus = 'healthy' | 'degraded';

export const LLM_PROVIDER_IDS: readonly LlmProviderId[] = [
  'local',
  'openrouter',
  'gemini',
  'claude',
  'zero-ai',
] as const;

export const LLM_PROVIDER_LABELS: Record<LlmProviderId, string> = {
  local: 'Local',
  openrouter: 'OpenRouter',
  gemini: 'Gemini',
  claude: 'Claude',
  'zero-ai': 'Zero-AI',
};

export const DEFAULT_PROVIDER_CONFIGS: Record<LlmProviderId, { baseUrl: string; model: string }> = {
  gemini: {
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    model: 'gemini-3.5-flash',
  },
  local: {
    baseUrl: 'http://localhost:11434/v1',
    model: '',
  },
  openrouter: {
    baseUrl: 'https://openrouter.ai/api/v1',
    model: 'google/gemini-3.5-flash',
  },
  claude: {
    baseUrl: 'https://api.anthropic.com/v1',
    model: 'claude-sonnet-4-20250514',
  },
  'zero-ai': {
    baseUrl: '',
    model: 'deterministic',
  },
};

export interface InternalProviderState {
  baseUrl: string;
  apiKey: string;
  model: string;
  keySource: LlmKeySource;
}

export interface ActiveLlmConfig {
  provider: LlmProviderId;
  baseUrl: string;
  apiKey: string;
  model: string;
  keySource: LlmKeySource;
  maxTokens: number;
}

export interface SanitizedProviderState {
  id: LlmProviderId;
  label: string;
  baseUrl: string;
  model: string;
  hasApiKey: boolean;
  keySource: LlmKeySource;
  maskedKey: string | null;
}

export interface ProbeResult {
  ok: boolean;
  status: LlmHealthStatus;
  provider: LlmProviderId;
  model: string;
  latencyMs: number;
  httpStatus?: number;
  message?: string;
  error?: string;
  checkedAt: string;
  cached?: boolean;
}

export interface SanitizedLlmConfig {
  activeProvider: LlmProviderId;
  activeProviderLabel: string;
  activeModel: string;
  aiEnabled: boolean;
  providers: Record<LlmProviderId, SanitizedProviderState>;
  lastProbe: ProbeResult | null;
}

export interface PersistedLlmSettings {
  activeProvider: LlmProviderId;
  providers: Partial<Record<LlmProviderId, { baseUrl: string; model: string }>>;
}

export interface DiscoveredModel {
  id: string;
  label: string;
  contextWindow?: number;
}

export interface DiscoverModelsResult {
  ok: boolean;
  provider: LlmProviderId;
  models: DiscoveredModel[];
  error?: string;
}

export interface UpdateLlmConfigInput {
  provider: LlmProviderId;
  baseUrl?: string;
  apiKey?: string;
  model?: string;
}

export interface TextCompletionRequest {
  system: string;
  prompt: string;
  maxTokens: number;
  temperature?: number;
  timeoutMs?: number;
}

export interface StructuredToolRequest {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  system: string;
  prompt: string;
  maxTokens: number;
  timeoutMs?: number;
}

export class LlmProviderError extends Error {
  readonly provider: LlmProviderId;
  readonly model: string;
  readonly httpStatus?: number;
  readonly normalizedMessage: string;

  constructor(params: {
    provider: LlmProviderId;
    model: string;
    normalizedMessage: string;
    httpStatus?: number;
  }) {
    super(params.normalizedMessage);
    this.name = 'LlmProviderError';
    this.provider = params.provider;
    this.model = params.model;
    this.httpStatus = params.httpStatus;
    this.normalizedMessage = params.normalizedMessage;
  }
}

/* -------------------------------------------------------------------------------------------------
 * Normalization & Sanitization Helpers
 * -----------------------------------------------------------------------------------------------*/

export function isProviderId(val: unknown): val is LlmProviderId {
  return typeof val === 'string' && (LLM_PROVIDER_IDS as readonly string[]).includes(val);
}

export function normalizeBaseUrl(raw: string): string {
  return raw.trim().replace(/\/+$/, '');
}

export function isValidHttpUrl(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  try {
    const parsed = new URL(trimmed);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function normalizeModelId(provider: LlmProviderId, rawModel: string): string {
  if (provider === 'zero-ai') return 'deterministic';
  const trimmed = rawModel.trim();
  if (provider === 'gemini') {
    return trimmed.replace(/^models\//i, '');
  }
  return trimmed;
}

export function resolveOpenAiEndpoint(baseUrl: string, suffix: '/chat/completions' | '/models'): string {
  const clean = normalizeBaseUrl(baseUrl);
  if (suffix === '/chat/completions') {
    if (clean.endsWith('/chat/completions')) return clean;
    if (clean.endsWith('/chat')) return `${clean}/completions`;
    return `${clean}/chat/completions`;
  }
  if (clean.endsWith('/chat/completions')) {
    return `${clean.slice(0, -'/chat/completions'.length)}/models`;
  }
  if (clean.endsWith('/models')) return clean;
  return `${clean}/models`;
}

export function resolveClaudeEndpoint(baseUrl: string, suffix: '/messages' | '/models'): string {
  const clean = normalizeBaseUrl(baseUrl || DEFAULT_PROVIDER_CONFIGS.claude.baseUrl);
  if (suffix === '/messages') {
    if (clean.endsWith('/messages')) return clean;
    if (clean.endsWith('/v1')) return `${clean}/messages`;
    return `${clean}/v1/messages`;
  }
  if (clean.endsWith('/messages')) {
    return `${clean.slice(0, -'/messages'.length)}/models`;
  }
  if (clean.endsWith('/models')) return clean;
  if (clean.endsWith('/v1')) return `${clean}/models`;
  return `${clean}/v1/models`;
}

export function maskApiKey(key?: string): string | null {
  const trimmed = (key ?? '').trim();
  if (!trimmed) return null;
  if (trimmed.length <= 4) return '••••';
  if (trimmed.length <= 10) return `••••${trimmed.slice(-3)}`;
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}

export function sanitizeErrorText(raw: string, secrets: readonly (string | undefined)[] = []): string {
  let out = raw;
  for (const s of secrets) {
    const trimmed = (s ?? '').trim();
    if (trimmed.length >= 4) {
      out = out.split(trimmed).join('[REDACTED]');
    }
  }
  out = out
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{6,}/gi, '$1[REDACTED]')
    .replace(/(x-api-key[:=\s]+)[A-Za-z0-9._~+/=-]{6,}/gi, '$1[REDACTED]')
    .replace(/([?&]key=)[^&\s"'<>]+/gi, '$1[REDACTED]')
    .replace(/\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-or-v1-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{12,}|sk-[A-Za-z0-9_-]{16,})\b/g, '[REDACTED]');
  return out;
}

function extractHostPort(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    return u.host;
  } catch {
    return baseUrl || 'localhost:11434';
  }
}

export function normalizeProviderError(params: {
  provider: LlmProviderId;
  model: string;
  baseUrl?: string;
  httpStatus?: number;
  rawBody?: string;
  err?: unknown;
  secrets?: readonly (string | undefined)[];
}): string {
  const label = LLM_PROVIDER_LABELS[params.provider];
  const secrets = params.secrets ?? [];
  const errObj = params.err as { name?: string; message?: string; code?: string; cause?: { code?: string; message?: string } } | undefined;
  const errName = errObj?.name ?? '';
  const errCode = errObj?.code ?? errObj?.cause?.code ?? '';
  const errMsg = [errObj?.message ?? '', errObj?.cause?.message ?? ''].filter(Boolean).join(' ');

  if (
    errName === 'TimeoutError' ||
    errName === 'AbortError' ||
    errCode === 'ETIMEDOUT' ||
    /timed?\s*out|aborted due to timeout/i.test(errMsg)
  ) {
    return `${label}: request timed out`;
  }

  if (
    errCode === 'ECONNREFUSED' ||
    errCode === 'ENOTFOUND' ||
    errCode === 'EAI_AGAIN' ||
    errCode === 'ECONNRESET' ||
    /ECONNREFUSED|ENOTFOUND|fetch failed|network error|connect\s+ECONN/i.test(errMsg)
  ) {
    if (params.provider === 'local') {
      return `Local: Ollama unreachable at ${extractHostPort(params.baseUrl || DEFAULT_PROVIDER_CONFIGS.local.baseUrl)}`;
    }
    return `${label}: server unreachable`;
  }

  const status = params.httpStatus;
  if (status !== undefined) {
    if (status === 401 || status === 403) {
      return `${label} ${status}: invalid or unauthorized API key`;
    }
    if (status === 404) {
      return `${label} 404: model "${params.model || '(none)'}" not found`;
    }
    if (status === 429) {
      return `${label} 429: rate limit or quota exceeded`;
    }
    if (status >= 500 && status <= 599) {
      return `${label} ${status}: upstream service error`;
    }
    const detail = sanitizeErrorText((params.rawBody ?? '').replace(/\s+/g, ' ').trim(), secrets).slice(0, 140);
    return detail ? `${label} ${status}: ${detail}` : `${label} ${status}: request failed`;
  }

  const cleaned = sanitizeErrorText(errMsg || 'unknown provider error', secrets).slice(0, 160);
  return `${label}: ${cleaned}`;
}

export function inferProviderFromEnvOrUrl(rawProvider?: string, baseUrl?: string, hasAnthropicKey?: boolean): LlmProviderId {
  const p = (rawProvider ?? '').trim().toLowerCase();
  if (p === 'local' || p === 'ollama') return 'local';
  if (p === 'openrouter') return 'openrouter';
  if (p === 'gemini' || p === 'google') return 'gemini';
  if (p === 'claude' || p === 'anthropic') return 'claude';
  if (p === 'zero-ai' || p === 'zero' || p === 'deterministic' || p === 'heuristic') return 'zero-ai';

  const url = (baseUrl ?? '').trim().toLowerCase();
  if (url) {
    if (url.includes('generativelanguage.googleapis.com')) return 'gemini';
    if (url.includes('openrouter.ai')) return 'openrouter';
    if (url.includes('api.anthropic.com')) return 'claude';
    if (
      url.includes('localhost') ||
      url.includes('127.0.0.1') ||
      url.includes('0.0.0.0') ||
      url.includes('host.docker.internal') ||
      url.includes(':11434')
    ) {
      return 'local';
    }
    return 'local';
  }

  if (hasAnthropicKey) return 'claude';
  return 'zero-ai';
}

export function providerIdToLegacyKind(provider: LlmProviderId): LlmProviderKind {
  if (provider === 'zero-ai') return 'heuristic';
  if (provider === 'claude') return 'anthropic';
  return 'openai-compatible';
}

/* -------------------------------------------------------------------------------------------------
 * Response Parsing Helpers
 * -----------------------------------------------------------------------------------------------*/

interface OpenAiChatResponse {
  choices?: Array<{
    message?: {
      content?: string | Array<{ type?: string; text?: string }> | null;
      tool_calls?: Array<{
        function?: { name?: string; arguments?: string | Record<string, unknown> };
      }>;
    };
  }>;
  error?: { message?: string };
}

interface AnthropicMessagesResponse {
  content?: Array<
    | { type: 'text'; text?: string }
    | { type: 'tool_use'; name?: string; input?: unknown }
  >;
  error?: { message?: string; type?: string };
}

function extractOpenAiMessageText(content: string | Array<{ type?: string; text?: string }> | null | undefined): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => (typeof part?.text === 'string' ? part.text : ''))
      .join('\n');
  }
  return '';
}

function extractJsonObject(raw: string): unknown {
  const trimmed = raw.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced?.[1]?.trim() ?? trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start !== -1 && end > start) {
      return JSON.parse(candidate.slice(start, end + 1));
    }
    throw new Error('Model response did not contain a valid JSON object');
  }
}

const NON_CHAT_GEMINI_RE =
  /(embedding|imagen|veo|aqa|tts|whisper|robotics|audio-only|learnlm-.*-audio|text-bison|chat-bison|gecko)/i;

const POPULAR_OPENROUTER_MODELS = [
  'google/gemini-3.5-flash',
  'google/gemini-2.5-pro',
  'anthropic/claude-sonnet-4',
  'anthropic/claude-opus-4',
  'anthropic/claude-3.7-sonnet',
  'qwen/qwen-2.5-coder-32b-instruct',
  'deepseek/deepseek-r1',
  'deepseek/deepseek-chat',
  'openai/gpt-4o',
  'openai/gpt-4o-mini',
  'meta-llama/llama-3.3-70b-instruct',
];

function geminiRank(id: string): number {
  const lower = id.toLowerCase();
  if (lower === 'gemini-3.5-flash') return 0;
  if (lower.startsWith('gemini-3.5-')) return 1;
  if (lower.startsWith('gemini-3')) return 2;
  if (lower.startsWith('gemini-2')) return 3;
  if (lower.includes('flash')) return 6;
  if (lower.includes('pro')) return 7;
  return 10;
}

function openRouterRank(id: string): number {
  const idx = POPULAR_OPENROUTER_MODELS.indexOf(id);
  if (idx !== -1) return idx;
  const lower = id.toLowerCase();
  if (lower.startsWith('google/gemini-3')) return 20;
  if (lower.startsWith('anthropic/claude-')) return 25;
  if (lower.startsWith('qwen/qwen')) return 30;
  if (lower.startsWith('openai/gpt-4')) return 35;
  if (lower.startsWith('deepseek/')) return 40;
  return 100;
}

/* -------------------------------------------------------------------------------------------------
 * RuntimeLlmStore
 * -----------------------------------------------------------------------------------------------*/

export interface RuntimeLlmStoreOptions {
  appConfig?: AppConfig;
  env?: NodeJS.ProcessEnv;
  fetchFn?: typeof fetch;
  nowFn?: () => number;
  probeCacheTtlMs?: number;
}

interface CachedHealthProbe {
  cacheKey: string;
  timestampMs: number;
  result: ProbeResult;
}

export class RuntimeLlmStore {
  private activeProvider: LlmProviderId;
  private readonly providers: Record<LlmProviderId, InternalProviderState>;
  private readonly maxTokens: number;
  private readonly fetchFn: typeof fetch;
  private readonly nowFn: () => number;
  private readonly probeCacheTtlMs: number;
  private cachedProbe: CachedHealthProbe | null = null;

  constructor(opts: RuntimeLlmStoreOptions = {}) {
    this.fetchFn = opts.fetchFn ?? globalThis.fetch;
    this.nowFn = opts.nowFn ?? (() => Date.now());
    this.probeCacheTtlMs = opts.probeCacheTtlMs ?? 60_000;
    const env = opts.env ?? {};
    const appCfg = opts.appConfig;
    const parsedMaxTokens = Number.parseInt(env.ANTHROPIC_MAX_TOKENS ?? '8192', 10);
    this.maxTokens = appCfg?.llm.maxTokens ?? (Number.isFinite(parsedMaxTokens) && parsedMaxTokens > 0 ? parsedMaxTokens : 8192);

    this.providers = {
      gemini: {
        baseUrl: DEFAULT_PROVIDER_CONFIGS.gemini.baseUrl,
        apiKey: '',
        model: DEFAULT_PROVIDER_CONFIGS.gemini.model,
        keySource: 'none',
      },
      local: {
        baseUrl: DEFAULT_PROVIDER_CONFIGS.local.baseUrl,
        apiKey: '',
        model: DEFAULT_PROVIDER_CONFIGS.local.model,
        keySource: 'none',
      },
      openrouter: {
        baseUrl: DEFAULT_PROVIDER_CONFIGS.openrouter.baseUrl,
        apiKey: '',
        model: DEFAULT_PROVIDER_CONFIGS.openrouter.model,
        keySource: 'none',
      },
      claude: {
        baseUrl: DEFAULT_PROVIDER_CONFIGS.claude.baseUrl,
        apiKey: '',
        model: DEFAULT_PROVIDER_CONFIGS.claude.model,
        keySource: 'none',
      },
      'zero-ai': {
        baseUrl: '',
        apiKey: '',
        model: 'deterministic',
        keySource: 'none',
      },
    };

    // 1. Hydrate provider-specific fallback env vars
    const geminiKey = (env.GEMINI_API_KEY ?? '').trim();
    if (geminiKey) {
      this.providers.gemini.apiKey = geminiKey;
      this.providers.gemini.keySource = 'env';
    }
    const openRouterKey = (env.OPENROUTER_API_KEY ?? '').trim();
    if (openRouterKey) {
      this.providers.openrouter.apiKey = openRouterKey;
      this.providers.openrouter.keySource = 'env';
    }
    const ollamaUrl = (env.OLLAMA_BASE_URL ?? '').trim();
    if (ollamaUrl) {
      this.providers.local.baseUrl = normalizeBaseUrl(ollamaUrl);
    }
    const anthropicKey = (appCfg?.anthropic.apiKey ?? env.ANTHROPIC_API_KEY ?? '').trim();
    if (anthropicKey) {
      this.providers.claude.apiKey = anthropicKey;
      this.providers.claude.keySource = 'env';
    }
    const anthropicModel = (env.ANTHROPIC_MODEL ?? (appCfg?.llm.provider === 'anthropic' ? appCfg.llm.model : '') ?? '').trim();
    if (anthropicModel) {
      this.providers.claude.model = anthropicModel;
    }

    // 2. Hydrate generic LLM_* vars or AppConfig.llm
    const genericBaseUrl = (appCfg?.llm.baseUrl ?? env.LLM_BASE_URL ?? '').trim();
    const genericApiKey = (
      (appCfg?.llm.provider === 'openai-compatible' ? appCfg.llm.apiKey : undefined) ??
      env.LLM_API_KEY ??
      ''
    ).trim();
    const genericModel = (
      (appCfg?.llm.provider === 'openai-compatible' ? appCfg.llm.model : undefined) ??
      env.LLM_MODEL ??
      ''
    ).trim();
    const explicitProvider = (env.LLM_PROVIDER ?? '').trim();

    this.activeProvider = inferProviderFromEnvOrUrl(
      explicitProvider,
      genericBaseUrl,
      Boolean(anthropicKey && (appCfg ? appCfg.llm.provider === 'anthropic' : true)),
    );

    if (genericBaseUrl && this.activeProvider !== 'zero-ai') {
      const target = this.providers[this.activeProvider];
      target.baseUrl = normalizeBaseUrl(genericBaseUrl);
      if (genericApiKey) {
        target.apiKey = genericApiKey;
        target.keySource = 'env';
      }
      if (genericModel) {
        target.model = normalizeModelId(this.activeProvider, genericModel);
      }
    } else if (this.activeProvider !== 'zero-ai') {
      const target = this.providers[this.activeProvider];
      if (genericApiKey && !target.apiKey) {
        target.apiKey = genericApiKey;
        target.keySource = 'env';
      }
      if (genericModel && this.activeProvider !== 'claude') {
        target.model = normalizeModelId(this.activeProvider, genericModel);
      }
    }
  }

  private getAllSecrets(): string[] {
    return LLM_PROVIDER_IDS.map((id) => this.providers[id].apiKey).filter(Boolean);
  }

  private makeProbeCacheKey(cfg: { provider: LlmProviderId; baseUrl: string; model: string; apiKey: string }): string {
    return `${cfg.provider}|${normalizeBaseUrl(cfg.baseUrl)}|${normalizeModelId(cfg.provider, cfg.model)}|${cfg.apiKey ? 'k' : 'n'}`;
  }

  getActiveConfig(): ActiveLlmConfig {
    const p = this.providers[this.activeProvider];
    return {
      provider: this.activeProvider,
      baseUrl: p.baseUrl,
      apiKey: p.apiKey,
      model: normalizeModelId(this.activeProvider, p.model),
      keySource: p.keySource,
      maxTokens: this.maxTokens,
    };
  }

  getProviderCredentials(provider: LlmProviderId): InternalProviderState {
    const p = this.providers[provider];
    return { ...p };
  }

  getLastProbe(): ProbeResult | null {
    return this.cachedProbe ? { ...this.cachedProbe.result } : null;
  }

  getSanitizedConfig(): SanitizedLlmConfig {
    const sanitizedProviders = {} as Record<LlmProviderId, SanitizedProviderState>;
    for (const id of LLM_PROVIDER_IDS) {
      const p = this.providers[id];
      sanitizedProviders[id] = {
        id,
        label: LLM_PROVIDER_LABELS[id],
        baseUrl: p.baseUrl,
        model: normalizeModelId(id, p.model),
        hasApiKey: Boolean(p.apiKey),
        keySource: p.apiKey ? p.keySource : 'none',
        maskedKey: maskApiKey(p.apiKey),
      };
    }
    const active = this.getActiveConfig();
    return {
      activeProvider: active.provider,
      activeProviderLabel: LLM_PROVIDER_LABELS[active.provider],
      activeModel: active.model,
      aiEnabled: active.provider !== 'zero-ai',
      providers: sanitizedProviders,
      lastProbe: this.getLastProbe(),
    };
  }

  exportPersistedSettings(): PersistedLlmSettings {
    const out: PersistedLlmSettings = {
      activeProvider: this.activeProvider,
      providers: {},
    };
    for (const id of LLM_PROVIDER_IDS) {
      if (id === 'zero-ai') continue;
      out.providers[id] = {
        baseUrl: this.providers[id].baseUrl,
        model: normalizeModelId(id, this.providers[id].model),
      };
    }
    return out;
  }

  hydratePersistedSettings(saved: PersistedLlmSettings | null | undefined): void {
    if (!saved || typeof saved !== 'object') return;
    if (saved.providers && typeof saved.providers === 'object') {
      for (const id of LLM_PROVIDER_IDS) {
        if (id === 'zero-ai') continue;
        const entry = saved.providers[id];
        if (!entry) continue;
        if (typeof entry.baseUrl === 'string' && isValidHttpUrl(entry.baseUrl)) {
          this.providers[id].baseUrl = normalizeBaseUrl(entry.baseUrl);
        }
        if (typeof entry.model === 'string' && entry.model.trim()) {
          this.providers[id].model = normalizeModelId(id, entry.model);
        }
      }
    }
    if (isProviderId(saved.activeProvider)) {
      const target = this.providers[saved.activeProvider];
      const canActivate =
        saved.activeProvider === 'zero-ai' ||
        saved.activeProvider === 'local' ||
        Boolean(target.apiKey);
      if (canActivate) {
        this.activeProvider = saved.activeProvider;
        this.invalidateProbeCache();
      }
    }
  }

  invalidateProbeCache(): void {
    this.cachedProbe = null;
  }

  updateConfig(input: UpdateLlmConfigInput): SanitizedLlmConfig {
    const provider = input.provider;
    if (!isProviderId(provider)) {
      throw new Error(`Unsupported LLM provider: ${String(provider)}`);
    }

    if (provider === 'zero-ai') {
      this.activeProvider = 'zero-ai';
      this.providers['zero-ai'].model = 'deterministic';
      this.invalidateProbeCache();
      return this.getSanitizedConfig();
    }

    const slot = this.providers[provider];

    if (input.baseUrl !== undefined) {
      const cleanUrl = normalizeBaseUrl(input.baseUrl);
      if (!isValidHttpUrl(cleanUrl)) {
        throw new Error('Base URL must start with http:// or https://');
      }
      slot.baseUrl = cleanUrl;
    } else if (!slot.baseUrl) {
      slot.baseUrl = DEFAULT_PROVIDER_CONFIGS[provider].baseUrl;
    }

    if (input.apiKey !== undefined && input.apiKey.trim().length > 0) {
      slot.apiKey = input.apiKey.trim();
      slot.keySource = 'runtime';
    }

    const nextModel =
      input.model !== undefined ? normalizeModelId(provider, input.model) : normalizeModelId(provider, slot.model);
    if (!nextModel) {
      throw new Error(`Model ID is required for ${LLM_PROVIDER_LABELS[provider]}`);
    }
    slot.model = nextModel;

    this.activeProvider = provider;
    this.invalidateProbeCache();
    return this.getSanitizedConfig();
  }

  recordLiveFailure(
    provider: LlmProviderId,
    model: string,
    baseUrl: string,
    normalizedError: string,
    httpStatus?: number,
  ): void {
    const active = this.getActiveConfig();
    if (active.provider !== provider) return;
    const cleanErr = sanitizeErrorText(normalizedError, this.getAllSecrets());
    const result: ProbeResult = {
      ok: false,
      status: 'degraded',
      provider,
      model: normalizeModelId(provider, model),
      latencyMs: 0,
      ...(httpStatus !== undefined ? { httpStatus } : {}),
      error: cleanErr,
      checkedAt: new Date(this.nowFn()).toISOString(),
    };
    this.cachedProbe = {
      cacheKey: this.makeProbeCacheKey({ provider, baseUrl, model, apiKey: active.apiKey }),
      timestampMs: this.nowFn(),
      result,
    };
  }

  recordLiveSuccess(provider: LlmProviderId, model: string, baseUrl: string, latencyMs: number): void {
    const active = this.getActiveConfig();
    if (active.provider !== provider) return;
    const result: ProbeResult = {
      ok: true,
      status: 'healthy',
      provider,
      model: normalizeModelId(provider, model),
      latencyMs,
      message: `Connected (${latencyMs}ms)`,
      checkedAt: new Date(this.nowFn()).toISOString(),
    };
    this.cachedProbe = {
      cacheKey: this.makeProbeCacheKey({ provider, baseUrl, model, apiKey: active.apiKey }),
      timestampMs: this.nowFn(),
      result,
    };
  }

  private resolveEffectiveConfig(input: {
    provider: LlmProviderId;
    baseUrl?: string;
    apiKey?: string;
    model?: string;
  }): ActiveLlmConfig {
    const stored = this.providers[input.provider];
    const baseUrl =
      input.provider === 'zero-ai'
        ? ''
        : normalizeBaseUrl(input.baseUrl?.trim() || stored.baseUrl || DEFAULT_PROVIDER_CONFIGS[input.provider].baseUrl);
    const trimmedKey = (input.apiKey ?? '').trim();
    const apiKey = trimmedKey || stored.apiKey;
    const keySource: LlmKeySource = trimmedKey ? 'runtime' : stored.apiKey ? stored.keySource : 'none';
    const model =
      input.provider === 'zero-ai'
        ? 'deterministic'
        : normalizeModelId(input.provider, input.model?.trim() || stored.model);

    return {
      provider: input.provider,
      baseUrl,
      apiKey,
      model,
      keySource,
      maxTokens: this.maxTokens,
    };
  }

  /* -----------------------------------------------------------------------------------------------
   * Unified Multi-Provider Execution Adapter
   * ---------------------------------------------------------------------------------------------*/

  private buildOpenAiHeaders(cfg: ActiveLlmConfig): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cfg.apiKey && (cfg.provider !== 'local' || cfg.apiKey.trim().length > 0)) {
      headers.Authorization = `Bearer ${cfg.apiKey}`;
    }
    if (cfg.provider === 'openrouter' || cfg.baseUrl.includes('openrouter.ai')) {
      headers['HTTP-Referer'] = 'https://github.com/spriteguard/spriteguard';
      headers['X-Title'] = 'SpriteGuard';
    }
    return headers;
  }

  private buildClaudeHeaders(apiKey: string): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    };
  }

  async completeText(req: TextCompletionRequest, override?: ActiveLlmConfig): Promise<{ text: string; latencyMs: number }> {
    const cfg = override ?? this.getActiveConfig();
    if (cfg.provider === 'zero-ai') {
      throw new LlmProviderError({
        provider: 'zero-ai',
        model: 'deterministic',
        normalizedMessage: 'Zero-AI mode is active',
      });
    }
    if (!isValidHttpUrl(cfg.baseUrl)) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]}: invalid base URL`,
      });
    }
    if (!cfg.model) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: '',
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]}: no model configured`,
      });
    }
    if (cfg.provider !== 'local' && !cfg.apiKey) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        httpStatus: 401,
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]} 401: invalid or unauthorized API key`,
      });
    }

    const started = this.nowFn();
    const timeoutMs = req.timeoutMs ?? 60_000;
    const secrets = [...this.getAllSecrets(), cfg.apiKey];

    try {
      if (cfg.provider === 'claude') {
        const endpoint = resolveClaudeEndpoint(cfg.baseUrl, '/messages');
        const res = await this.fetchFn(endpoint, {
          method: 'POST',
          headers: this.buildClaudeHeaders(cfg.apiKey),
          body: JSON.stringify({
            model: cfg.model,
            max_tokens: req.maxTokens,
            system: req.system,
            ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
            messages: [{ role: 'user', content: req.prompt }],
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const rawText = await res.text();
        let json: AnthropicMessagesResponse = {};
        try {
          json = JSON.parse(rawText) as AnthropicMessagesResponse;
        } catch {
          /* ignore */
        }
        if (!res.ok) {
          const normalized = normalizeProviderError({
            provider: cfg.provider,
            model: cfg.model,
            baseUrl: cfg.baseUrl,
            httpStatus: res.status,
            rawBody: json.error?.message ?? rawText,
            secrets,
          });
          throw new LlmProviderError({
            provider: cfg.provider,
            model: cfg.model,
            httpStatus: res.status,
            normalizedMessage: normalized,
          });
        }
        const text = (json.content ?? [])
          .filter((b): b is { type: 'text'; text?: string } => b.type === 'text')
          .map((b) => b.text ?? '')
          .join('\n')
          .trim();
        return { text, latencyMs: Math.max(0, this.nowFn() - started) };
      }

      // OpenAI-compatible adapter (Gemini, OpenRouter, Local Ollama)
      const endpoint = resolveOpenAiEndpoint(cfg.baseUrl, '/chat/completions');
      const res = await this.fetchFn(endpoint, {
        method: 'POST',
        headers: this.buildOpenAiHeaders(cfg),
        body: JSON.stringify({
          model: normalizeModelId(cfg.provider, cfg.model),
          max_tokens: req.maxTokens,
          ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
          messages: [
            { role: 'system', content: req.system },
            { role: 'user', content: req.prompt },
          ],
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      const rawText = await res.text();
      let json: OpenAiChatResponse = {};
      try {
        json = JSON.parse(rawText) as OpenAiChatResponse;
      } catch {
        /* ignore */
      }
      if (!res.ok) {
        const normalized = normalizeProviderError({
          provider: cfg.provider,
          model: cfg.model,
          baseUrl: cfg.baseUrl,
          httpStatus: res.status,
          rawBody: json.error?.message ?? rawText,
          secrets,
        });
        throw new LlmProviderError({
          provider: cfg.provider,
          model: cfg.model,
          httpStatus: res.status,
          normalizedMessage: normalized,
        });
      }
      const text = extractOpenAiMessageText(json.choices?.[0]?.message?.content).trim();
      return { text, latencyMs: Math.max(0, this.nowFn() - started) };
    } catch (err) {
      if (err instanceof LlmProviderError) throw err;
      const normalized = normalizeProviderError({
        provider: cfg.provider,
        model: cfg.model,
        baseUrl: cfg.baseUrl,
        err,
        secrets,
      });
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        normalizedMessage: normalized,
      });
    }
  }

  async completeStructuredTool(req: StructuredToolRequest, override?: ActiveLlmConfig): Promise<{ data: unknown; latencyMs: number }> {
    const cfg = override ?? this.getActiveConfig();
    if (cfg.provider === 'zero-ai') {
      throw new LlmProviderError({
        provider: 'zero-ai',
        model: 'deterministic',
        normalizedMessage: 'Zero-AI mode is active',
      });
    }
    if (!isValidHttpUrl(cfg.baseUrl)) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]}: invalid base URL`,
      });
    }
    if (!cfg.model) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: '',
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]}: no model configured`,
      });
    }
    if (cfg.provider !== 'local' && !cfg.apiKey) {
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        httpStatus: 401,
        normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]} 401: invalid or unauthorized API key`,
      });
    }

    const started = this.nowFn();
    const timeoutMs = req.timeoutMs ?? 120_000;
    const secrets = [...this.getAllSecrets(), cfg.apiKey];

    try {
      if (cfg.provider === 'claude') {
        const endpoint = resolveClaudeEndpoint(cfg.baseUrl, '/messages');
        const res = await this.fetchFn(endpoint, {
          method: 'POST',
          headers: this.buildClaudeHeaders(cfg.apiKey),
          body: JSON.stringify({
            model: cfg.model,
            max_tokens: req.maxTokens,
            system: req.system,
            tools: [
              {
                name: req.name,
                description: req.description,
                input_schema: req.schema,
              },
            ],
            tool_choice: { type: 'tool', name: req.name },
            messages: [{ role: 'user', content: req.prompt }],
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const rawText = await res.text();
        let json: AnthropicMessagesResponse = {};
        try {
          json = JSON.parse(rawText) as AnthropicMessagesResponse;
        } catch {
          /* ignore */
        }
        if (!res.ok) {
          const normalized = normalizeProviderError({
            provider: cfg.provider,
            model: cfg.model,
            baseUrl: cfg.baseUrl,
            httpStatus: res.status,
            rawBody: json.error?.message ?? rawText,
            secrets,
          });
          throw new LlmProviderError({
            provider: cfg.provider,
            model: cfg.model,
            httpStatus: res.status,
            normalizedMessage: normalized,
          });
        }
        const toolBlock = (json.content ?? []).find(
          (b): b is { type: 'tool_use'; name?: string; input?: unknown } => b.type === 'tool_use' && b.name === req.name,
        );
        if (!toolBlock) {
          throw new LlmProviderError({
            provider: cfg.provider,
            model: cfg.model,
            normalizedMessage: `Claude did not invoke ${req.name}`,
          });
        }
        return { data: toolBlock.input, latencyMs: Math.max(0, this.nowFn() - started) };
      }

      // OpenAI-compatible tool call with automatic 400/422 JSON fallback
      const endpoint = resolveOpenAiEndpoint(cfg.baseUrl, '/chat/completions');
      const postChat = async (body: Record<string, unknown>) => {
        const res = await this.fetchFn(endpoint, {
          method: 'POST',
          headers: this.buildOpenAiHeaders(cfg),
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const text = await res.text();
        let json: OpenAiChatResponse = {};
        try {
          json = JSON.parse(text) as OpenAiChatResponse;
        } catch {
          /* ignore */
        }
        return { ok: res.ok, status: res.status, json, text };
      };

      const modelId = normalizeModelId(cfg.provider, cfg.model);
      const primary = await postChat({
        model: modelId,
        max_tokens: req.maxTokens,
        messages: [
          { role: 'system', content: req.system },
          { role: 'user', content: req.prompt },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: req.name,
              description: req.description,
              parameters: req.schema,
            },
          },
        ],
        tool_choice: { type: 'function', function: { name: req.name } },
      });

      if (primary.ok) {
        const msg = primary.json.choices?.[0]?.message;
        const toolCalls = msg?.tool_calls;
        if (Array.isArray(toolCalls) && toolCalls.length > 0) {
          const match = toolCalls.find((tc) => tc.function?.name === req.name) ?? toolCalls[0];
          const rawArgs = match?.function?.arguments;
          if (typeof rawArgs === 'string') {
            return { data: extractJsonObject(rawArgs), latencyMs: Math.max(0, this.nowFn() - started) };
          }
          if (rawArgs && typeof rawArgs === 'object') {
            return { data: rawArgs, latencyMs: Math.max(0, this.nowFn() - started) };
          }
        }
        const contentText = extractOpenAiMessageText(msg?.content);
        if (contentText.trim()) {
          return { data: extractJsonObject(contentText), latencyMs: Math.max(0, this.nowFn() - started) };
        }
        throw new LlmProviderError({
          provider: cfg.provider,
          model: cfg.model,
          normalizedMessage: `${LLM_PROVIDER_LABELS[cfg.provider]}: response contained neither tool_calls nor content`,
        });
      }

      if (primary.status === 400 || primary.status === 422) {
        const jsonSystem =
          `${req.system}\n\nRespond ONLY with a single valid JSON object matching this schema (no markdown, no explanation):\n` +
          JSON.stringify(req.schema);
        let fallback = await postChat({
          model: modelId,
          max_tokens: req.maxTokens,
          messages: [
            { role: 'system', content: jsonSystem },
            { role: 'user', content: req.prompt },
          ],
          response_format: { type: 'json_object' },
        });
        if (!fallback.ok && (fallback.status === 400 || fallback.status === 422)) {
          fallback = await postChat({
            model: modelId,
            max_tokens: req.maxTokens,
            messages: [
              { role: 'system', content: jsonSystem },
              { role: 'user', content: req.prompt },
            ],
          });
        }
        if (!fallback.ok) {
          const normalized = normalizeProviderError({
            provider: cfg.provider,
            model: cfg.model,
            baseUrl: cfg.baseUrl,
            httpStatus: fallback.status,
            rawBody: fallback.json.error?.message ?? fallback.text,
            secrets,
          });
          throw new LlmProviderError({
            provider: cfg.provider,
            model: cfg.model,
            httpStatus: fallback.status,
            normalizedMessage: normalized,
          });
        }
        const text = extractOpenAiMessageText(fallback.json.choices?.[0]?.message?.content);
        return { data: extractJsonObject(text), latencyMs: Math.max(0, this.nowFn() - started) };
      }

      const normalized = normalizeProviderError({
        provider: cfg.provider,
        model: cfg.model,
        baseUrl: cfg.baseUrl,
        httpStatus: primary.status,
        rawBody: primary.json.error?.message ?? primary.text,
        secrets,
      });
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        httpStatus: primary.status,
        normalizedMessage: normalized,
      });
    } catch (err) {
      if (err instanceof LlmProviderError) throw err;
      const normalized = normalizeProviderError({
        provider: cfg.provider,
        model: cfg.model,
        baseUrl: cfg.baseUrl,
        err,
        secrets,
      });
      throw new LlmProviderError({
        provider: cfg.provider,
        model: cfg.model,
        normalizedMessage: normalized,
      });
    }
  }

  /* -----------------------------------------------------------------------------------------------
   * Live Model Auto-Discovery (6s Timeout)
   * ---------------------------------------------------------------------------------------------*/

  async discoverModels(input: {
    provider: LlmProviderId;
    baseUrl?: string;
    apiKey?: string;
  }): Promise<DiscoverModelsResult> {
    const provider = input.provider;
    if (provider === 'zero-ai') {
      return {
        ok: true,
        provider: 'zero-ai',
        models: [{ id: 'deterministic', label: 'Deterministic Security Engine (Offline)' }],
      };
    }

    const cfg = this.resolveEffectiveConfig(input);
    const secrets = [...this.getAllSecrets(), cfg.apiKey];

    if (!isValidHttpUrl(cfg.baseUrl)) {
      return {
        ok: false,
        provider,
        models: [],
        error: 'Base URL must start with http:// or https://',
      };
    }

    if ((provider === 'gemini' || provider === 'claude') && !cfg.apiKey) {
      return {
        ok: false,
        provider,
        models: [],
        error: `${LLM_PROVIDER_LABELS[provider]}: API key is required to detect models`,
      };
    }

    const timeoutMs = 6_000;

    try {
      if (provider === 'gemini') {
        const models = await this.discoverGeminiModels(cfg, timeoutMs, secrets);
        return { ok: true, provider, models };
      }

      if (provider === 'local') {
        const models = await this.discoverLocalModels(cfg, timeoutMs, secrets);
        return { ok: true, provider, models };
      }

      if (provider === 'openrouter') {
        const endpoint = resolveOpenAiEndpoint(cfg.baseUrl, '/models');
        const res = await this.fetchFn(endpoint, {
          method: 'GET',
          headers: this.buildOpenAiHeaders(cfg),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const rawText = await res.text();
        if (!res.ok) {
          return {
            ok: false,
            provider,
            models: [],
            error: normalizeProviderError({
              provider,
              model: cfg.model,
              baseUrl: cfg.baseUrl,
              httpStatus: res.status,
              rawBody: rawText,
              secrets,
            }),
          };
        }
        const parsed = JSON.parse(rawText) as {
          data?: Array<{ id?: string; name?: string; context_length?: number }>;
        };
        const list = (parsed.data ?? [])
          .filter((m): m is { id: string; name?: string; context_length?: number } => typeof m?.id === 'string' && m.id.length > 0)
          .map((m) => ({
            id: m.id,
            label: m.name && m.name !== m.id ? `${m.id} — ${m.name}` : m.id,
            ...(typeof m.context_length === 'number' ? { contextWindow: m.context_length } : {}),
          }));
        list.sort((a, b) => {
          const ra = openRouterRank(a.id);
          const rb = openRouterRank(b.id);
          return ra !== rb ? ra - rb : a.id.localeCompare(b.id);
        });
        return { ok: true, provider, models: list };
      }

      if (provider === 'claude') {
        const endpoint = resolveClaudeEndpoint(cfg.baseUrl, '/models');
        const res = await this.fetchFn(endpoint, {
          method: 'GET',
          headers: this.buildClaudeHeaders(cfg.apiKey),
          signal: AbortSignal.timeout(timeoutMs),
        });
        const rawText = await res.text();
        if (!res.ok) {
          return {
            ok: false,
            provider,
            models: [],
            error: normalizeProviderError({
              provider,
              model: cfg.model,
              baseUrl: cfg.baseUrl,
              httpStatus: res.status,
              rawBody: rawText,
              secrets,
            }),
          };
        }
        const parsed = JSON.parse(rawText) as {
          data?: Array<{ id?: string; display_name?: string }>;
        };
        const list = (parsed.data ?? [])
          .filter((m): m is { id: string; display_name?: string } => typeof m?.id === 'string' && m.id.length > 0)
          .map((m) => ({
            id: m.id,
            label: m.display_name && m.display_name !== m.id ? `${m.id} — ${m.display_name}` : m.id,
          }));
        return { ok: true, provider, models: list };
      }

      return { ok: false, provider, models: [], error: `Unsupported provider: ${provider}` };
    } catch (err) {
      if (err instanceof LlmProviderError) {
        return { ok: false, provider, models: [], error: err.normalizedMessage };
      }
      return {
        ok: false,
        provider,
        models: [],
        error: normalizeProviderError({
          provider,
          model: cfg.model,
          baseUrl: cfg.baseUrl,
          err,
          secrets,
        }),
      };
    }
  }

  private async discoverGeminiModels(
    cfg: ActiveLlmConfig,
    timeoutMs: number,
    secrets: readonly string[],
  ): Promise<DiscoveredModel[]> {
    const parseOpenAiGemini = (rawText: string): DiscoveredModel[] => {
      const parsed = JSON.parse(rawText) as { data?: Array<{ id?: string; display_name?: string }> };
      return (parsed.data ?? [])
        .map((m) => normalizeModelId('gemini', String(m?.id ?? '')))
        .filter((id) => Boolean(id) && !NON_CHAT_GEMINI_RE.test(id))
        .map((id) => ({ id, label: id }));
    };

    const parseNativeGemini = (rawText: string): DiscoveredModel[] => {
      const parsed = JSON.parse(rawText) as {
        models?: Array<{
          name?: string;
          displayName?: string;
          inputTokenLimit?: number;
          supportedGenerationMethods?: string[];
        }>;
      };
      return (parsed.models ?? [])
        .filter((m) => {
          if (Array.isArray(m.supportedGenerationMethods) && !m.supportedGenerationMethods.includes('generateContent')) {
            return false;
          }
          const id = normalizeModelId('gemini', String(m?.name ?? ''));
          return Boolean(id) && !NON_CHAT_GEMINI_RE.test(id);
        })
        .map((m) => {
          const id = normalizeModelId('gemini', String(m.name ?? ''));
          return {
            id,
            label: m.displayName && m.displayName !== id ? `${id} — ${m.displayName}` : id,
            ...(typeof m.inputTokenLimit === 'number' ? { contextWindow: m.inputTokenLimit } : {}),
          };
        });
    };

    let primaryStatus: number | undefined;
    let primaryBody = '';
    const openAiUrl = resolveOpenAiEndpoint(cfg.baseUrl, '/models');
    try {
      const res = await this.fetchFn(openAiUrl, {
        method: 'GET',
        headers: this.buildOpenAiHeaders(cfg),
        signal: AbortSignal.timeout(timeoutMs),
      });
      primaryStatus = res.status;
      primaryBody = await res.text();
      if (res.ok) {
        const models = parseOpenAiGemini(primaryBody);
        if (models.length > 0) {
          return dedupeAndSortGemini(models);
        }
      }
      // If auth failed explicitly, don't retry with a second request unless needed
      if (res.status === 401 || res.status === 403) {
        throw new LlmProviderError({
          provider: 'gemini',
          model: cfg.model,
          httpStatus: res.status,
          normalizedMessage: normalizeProviderError({
            provider: 'gemini',
            model: cfg.model,
            baseUrl: cfg.baseUrl,
            httpStatus: res.status,
            rawBody: primaryBody,
            secrets,
          }),
        });
      }
    } catch (err) {
      if (err instanceof LlmProviderError) throw err;
    }

    // Fallback: native Gemini v1beta models endpoint
    const nativeUrl = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(cfg.apiKey)}`;
    const fallbackRes = await this.fetchFn(nativeUrl, {
      method: 'GET',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const fallbackBody = await fallbackRes.text();
    if (!fallbackRes.ok) {
      throw new LlmProviderError({
        provider: 'gemini',
        model: cfg.model,
        httpStatus: fallbackRes.status || primaryStatus,
        normalizedMessage: normalizeProviderError({
          provider: 'gemini',
          model: cfg.model,
          baseUrl: cfg.baseUrl,
          httpStatus: fallbackRes.status || primaryStatus,
          rawBody: fallbackBody || primaryBody,
          secrets,
        }),
      });
    }
    return dedupeAndSortGemini(parseNativeGemini(fallbackBody));
  }

  private async discoverLocalModels(
    cfg: ActiveLlmConfig,
    timeoutMs: number,
    secrets: readonly string[],
  ): Promise<DiscoveredModel[]> {
    let firstErr: unknown = null;
    const openAiUrl = resolveOpenAiEndpoint(cfg.baseUrl, '/models');
    try {
      const res = await this.fetchFn(openAiUrl, {
        method: 'GET',
        headers: this.buildOpenAiHeaders(cfg),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) {
        const rawText = await res.text();
        const parsed = JSON.parse(rawText) as { data?: Array<{ id?: string }> };
        const models = (parsed.data ?? [])
          .filter((m): m is { id: string } => typeof m?.id === 'string' && m.id.trim().length > 0)
          .map((m) => ({ id: m.id.trim(), label: m.id.trim() }));
        if (models.length > 0) return dedupeModels(models);
      }
    } catch (err) {
      firstErr = err;
    }

    // Fallback to native Ollama /api/tags
    try {
      const origin = new URL(cfg.baseUrl).origin;
      const res = await this.fetchFn(`${origin}/api/tags`, {
        method: 'GET',
        signal: AbortSignal.timeout(timeoutMs),
      });
      const rawText = await res.text();
      if (!res.ok) {
        throw new LlmProviderError({
          provider: 'local',
          model: cfg.model,
          httpStatus: res.status,
          normalizedMessage: normalizeProviderError({
            provider: 'local',
            model: cfg.model,
            baseUrl: cfg.baseUrl,
            httpStatus: res.status,
            rawBody: rawText,
            secrets,
          }),
        });
      }
      const parsed = JSON.parse(rawText) as { models?: Array<{ name?: string; model?: string }> };
      const models = (parsed.models ?? [])
        .map((m) => (m?.name ?? m?.model ?? '').trim())
        .filter(Boolean)
        .map((id) => ({ id, label: id }));
      return dedupeModels(models);
    } catch (err) {
      if (err instanceof LlmProviderError) throw err;
      throw new LlmProviderError({
        provider: 'local',
        model: cfg.model,
        normalizedMessage: normalizeProviderError({
          provider: 'local',
          model: cfg.model,
          baseUrl: cfg.baseUrl,
          err: err ?? firstErr,
          secrets,
        }),
      });
    }
  }

  /* -----------------------------------------------------------------------------------------------
   * Live Connection Verification Probe & 60s Health Cache
   * ---------------------------------------------------------------------------------------------*/

  async probeConnection(
    input: { provider: LlmProviderId; baseUrl?: string; apiKey?: string; model?: string },
    opts: { prompt?: string; maxTokens?: number; timeoutMs?: number } = {},
  ): Promise<ProbeResult> {
    const checkedAt = new Date(this.nowFn()).toISOString();
    if (input.provider === 'zero-ai') {
      return {
        ok: true,
        status: 'healthy',
        provider: 'zero-ai',
        model: 'deterministic',
        latencyMs: 0,
        message: 'Zero-AI deterministic mode active',
        checkedAt,
      };
    }

    const cfg = this.resolveEffectiveConfig(input);
    if (!isValidHttpUrl(cfg.baseUrl)) {
      return {
        ok: false,
        status: 'degraded',
        provider: cfg.provider,
        model: cfg.model,
        latencyMs: 0,
        error: 'Base URL must start with http:// or https://',
        checkedAt,
      };
    }
    if (!cfg.model) {
      return {
        ok: false,
        status: 'degraded',
        provider: cfg.provider,
        model: '',
        latencyMs: 0,
        error: `${LLM_PROVIDER_LABELS[cfg.provider]}: model ID is required`,
        checkedAt,
      };
    }
    if (cfg.provider !== 'local' && !cfg.apiKey) {
      return {
        ok: false,
        status: 'degraded',
        provider: cfg.provider,
        model: cfg.model,
        latencyMs: 0,
        httpStatus: 401,
        error: `${LLM_PROVIDER_LABELS[cfg.provider]} 401: invalid or unauthorized API key`,
        checkedAt,
      };
    }

    const started = this.nowFn();
    try {
      const { latencyMs } = await this.completeText(
        {
          system: 'Reply concisely.',
          prompt: opts.prompt ?? 'Reply OK',
          maxTokens: opts.maxTokens ?? 8,
          temperature: 0,
          timeoutMs: opts.timeoutMs ?? 8_000,
        },
        cfg,
      );
      return {
        ok: true,
        status: 'healthy',
        provider: cfg.provider,
        model: cfg.model,
        latencyMs,
        message: `Connected (${latencyMs}ms)`,
        checkedAt: new Date(this.nowFn()).toISOString(),
      };
    } catch (err) {
      const latencyMs = Math.max(0, this.nowFn() - started);
      if (err instanceof LlmProviderError) {
        return {
          ok: false,
          status: 'degraded',
          provider: cfg.provider,
          model: cfg.model,
          latencyMs,
          ...(err.httpStatus !== undefined ? { httpStatus: err.httpStatus } : {}),
          error: sanitizeErrorText(err.normalizedMessage, [...this.getAllSecrets(), cfg.apiKey]),
          checkedAt: new Date(this.nowFn()).toISOString(),
        };
      }
      return {
        ok: false,
        status: 'degraded',
        provider: cfg.provider,
        model: cfg.model,
        latencyMs,
        error: normalizeProviderError({
          provider: cfg.provider,
          model: cfg.model,
          baseUrl: cfg.baseUrl,
          err,
          secrets: [...this.getAllSecrets(), cfg.apiKey],
        }),
        checkedAt: new Date(this.nowFn()).toISOString(),
      };
    }
  }

  async getCachedHealthProbe(opts: { force?: boolean } = {}): Promise<ProbeResult> {
    const active = this.getActiveConfig();
    if (active.provider === 'zero-ai') {
      const result: ProbeResult = {
        ok: true,
        status: 'healthy',
        provider: 'zero-ai',
        model: 'deterministic',
        latencyMs: 0,
        message: 'Zero-AI deterministic mode active',
        checkedAt: new Date(this.nowFn()).toISOString(),
        cached: false,
      };
      this.cachedProbe = {
        cacheKey: this.makeProbeCacheKey(active),
        timestampMs: this.nowFn(),
        result,
      };
      return result;
    }

    const cacheKey = this.makeProbeCacheKey(active);
    const now = this.nowFn();
    if (
      !opts.force &&
      this.cachedProbe &&
      this.cachedProbe.cacheKey === cacheKey &&
      now - this.cachedProbe.timestampMs < this.probeCacheTtlMs
    ) {
      return { ...this.cachedProbe.result, cached: true };
    }

    const fresh = await this.probeConnection(
      {
        provider: active.provider,
        baseUrl: active.baseUrl,
        apiKey: active.apiKey,
        model: active.model,
      },
      { prompt: 'OK', maxTokens: 1, timeoutMs: 5_000 },
    );
    const result: ProbeResult = { ...fresh, cached: false };
    this.cachedProbe = {
      cacheKey,
      timestampMs: this.nowFn(),
      result,
    };
    return result;
  }
}

function dedupeModels(models: DiscoveredModel[]): DiscoveredModel[] {
  const seen = new Set<string>();
  const out: DiscoveredModel[] = [];
  for (const m of models) {
    if (!seen.has(m.id)) {
      seen.add(m.id);
      out.push(m);
    }
  }
  return out;
}

function dedupeAndSortGemini(models: DiscoveredModel[]): DiscoveredModel[] {
  const unique = dedupeModels(models);
  unique.sort((a, b) => {
    const ra = geminiRank(a.id);
    const rb = geminiRank(b.id);
    return ra !== rb ? ra - rb : a.id.localeCompare(b.id);
  });
  return unique;
}
