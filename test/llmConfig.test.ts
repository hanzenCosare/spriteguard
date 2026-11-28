import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/index.js';
import {
  DEFAULT_PROVIDER_CONFIGS,
  RuntimeLlmStore,
  normalizeModelId,
  sanitizeErrorText,
} from '../src/services/llmConfig.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('DEFAULT_PROVIDER_CONFIGS uses gemini-3.5-flash (never legacy gemini-2.5-flash)', () => {
  assert.equal(DEFAULT_PROVIDER_CONFIGS.gemini.model, 'gemini-3.5-flash');
  assert.equal(DEFAULT_PROVIDER_CONFIGS.gemini.baseUrl, 'https://generativelanguage.googleapis.com/v1beta/openai');
  assert.equal(DEFAULT_PROVIDER_CONFIGS.openrouter.model, 'google/gemini-3.5-flash');
  assert.equal(normalizeModelId('gemini', 'models/gemini-3.5-flash'), 'gemini-3.5-flash');
});

test('RuntimeLlmStore preserves per-provider credentials across switches and never leaks raw keys', () => {
  const secretGemini = 'AIzaSyFakeGeminiSecretKey1234567890';
  const secretClaude = 'sk-ant-api03-FakeClaudeSecretKey987654321';

  const store = new RuntimeLlmStore({
    env: {
      LLM_PROVIDER: 'gemini',
      GEMINI_API_KEY: secretGemini,
      ANTHROPIC_API_KEY: secretClaude,
    },
  });

  // Booted on Gemini with env key
  let cfg = store.getSanitizedConfig();
  assert.equal(cfg.activeProvider, 'gemini');
  assert.equal(cfg.activeModel, 'gemini-3.5-flash');
  assert.equal(cfg.providers.gemini.hasApiKey, true);
  assert.equal(cfg.providers.gemini.keySource, 'env');
  assert.equal(cfg.providers.claude.hasApiKey, true);
  assert.equal(cfg.providers.claude.keySource, 'env');

  // Switch Gemini -> Zero-AI -> Gemini without supplying apiKey again
  store.updateConfig({ provider: 'zero-ai' });
  cfg = store.getSanitizedConfig();
  assert.equal(cfg.activeProvider, 'zero-ai');
  assert.equal(cfg.activeModel, 'deterministic');
  assert.equal(cfg.providers.gemini.hasApiKey, true);

  store.updateConfig({ provider: 'gemini', model: 'models/gemini-3.5-pro' });
  cfg = store.getSanitizedConfig();
  assert.equal(cfg.activeProvider, 'gemini');
  assert.equal(cfg.activeModel, 'gemini-3.5-pro');
  assert.equal(cfg.providers.gemini.hasApiKey, true);
  assert.equal(cfg.providers.gemini.keySource, 'env');
  assert.equal(store.getActiveConfig().apiKey, secretGemini);

  // Switch to Claude preserving env key
  store.updateConfig({ provider: 'claude', model: 'claude-sonnet-4-20250514' });
  assert.equal(store.getActiveConfig().apiKey, secretClaude);

  // Zero-secret-leak check on sanitized config & error sanitizer
  const serialized = JSON.stringify(store.getSanitizedConfig());
  assert.ok(!serialized.includes(secretGemini), 'sanitized config leaked Gemini key');
  assert.ok(!serialized.includes(secretClaude), 'sanitized config leaked Claude key');
  const scrubbed = sanitizeErrorText(
    `Auth failed for Bearer ${secretGemini} and x-api-key: ${secretClaude}`,
    [secretGemini, secretClaude],
  );
  assert.ok(!scrubbed.includes(secretGemini));
  assert.ok(!scrubbed.includes(secretClaude));
});

test('Model auto-discovery normalizes Gemini models, falls back to Ollama /api/tags, sorts OpenRouter, and queries Claude', async () => {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    calls.push({ url, headers });

    if (url.includes('generativelanguage.googleapis.com/v1beta/openai/models')) {
      return jsonResponse({ error: { message: 'not found' } }, 404);
    }
    if (url.includes('generativelanguage.googleapis.com/v1beta/models?key=')) {
      return jsonResponse({
        models: [
          { name: 'models/text-embedding-004', supportedGenerationMethods: ['embedContent'] },
          { name: 'models/imagen-3.0-generate-002', supportedGenerationMethods: ['generateContent'] },
          { name: 'models/veo-2.0-generate-001', supportedGenerationMethods: ['generateContent'] },
          { name: 'models/gemini-3.5-flash', displayName: 'Gemini 3.5 Flash', supportedGenerationMethods: ['generateContent'] },
          { name: 'models/gemini-3.5-pro', displayName: 'Gemini 3.5 Pro', supportedGenerationMethods: ['generateContent'] },
          { name: 'models/aqa', supportedGenerationMethods: ['generateAnswer'] },
        ],
      });
    }
    if (url === 'http://localhost:11434/v1/models') {
      return jsonResponse({ error: 'unsupported' }, 404);
    }
    if (url === 'http://localhost:11434/api/tags') {
      return jsonResponse({
        models: [{ name: 'qwen2.5-coder:14b' }, { name: 'llama3.2:latest' }],
      });
    }
    if (url === 'https://openrouter.ai/api/v1/models') {
      return jsonResponse({
        data: [
          { id: 'zzz/obscure-model', name: 'Obscure Model', context_length: 8192 },
          { id: 'google/gemini-3.5-flash', name: 'Gemini 3.5 Flash', context_length: 1000000 },
          { id: 'qwen/qwen-2.5-coder-32b-instruct', name: 'Qwen 2.5 Coder 32B', context_length: 32768 },
        ],
      });
    }
    if (url === 'https://api.anthropic.com/v1/models') {
      return jsonResponse({
        data: [
          { id: 'claude-sonnet-4-20250514', display_name: 'Claude Sonnet 4' },
          { id: 'claude-opus-4-20250514', display_name: 'Claude Opus 4' },
        ],
      });
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  };

  const store = new RuntimeLlmStore({
    env: {
      GEMINI_API_KEY: 'AIzaSyTestDiscoveryKey99999',
      OPENROUTER_API_KEY: 'sk-or-v1-TestOpenRouterKey999',
      ANTHROPIC_API_KEY: 'sk-ant-TestClaudeKey999999',
    },
    fetchFn: mockFetch,
  });

  // 1. Gemini: strips models/ prefix and filters out embedding/imagen/veo/aqa
  const gem = await store.discoverModels({ provider: 'gemini' });
  assert.equal(gem.ok, true);
  assert.deepEqual(
    gem.models.map((m) => m.id),
    ['gemini-3.5-flash', 'gemini-3.5-pro'],
  );

  // 2. Local Ollama: falls back to /api/tags
  const loc = await store.discoverModels({ provider: 'local' });
  assert.equal(loc.ok, true);
  assert.deepEqual(
    loc.models.map((m) => m.id),
    ['qwen2.5-coder:14b', 'llama3.2:latest'],
  );

  // 3. OpenRouter: popular models sorted to top + headers included
  const or = await store.discoverModels({ provider: 'openrouter' });
  assert.equal(or.ok, true);
  assert.equal(or.models[0]?.id, 'google/gemini-3.5-flash');
  assert.equal(or.models[1]?.id, 'qwen/qwen-2.5-coder-32b-instruct');
  const orCall = calls.find((c) => c.url === 'https://openrouter.ai/api/v1/models');
  assert.equal(orCall?.headers['x-title'], 'SpriteGuard');

  // 4. Claude: native headers x-api-key + anthropic-version
  const cl = await store.discoverModels({ provider: 'claude' });
  assert.equal(cl.ok, true);
  assert.equal(cl.models[0]?.id, 'claude-sonnet-4-20250514');
  const clCall = calls.find((c) => c.url === 'https://api.anthropic.com/v1/models');
  assert.equal(clCall?.headers['anthropic-version'], '2023-06-01');
  assert.equal(clCall?.headers['x-api-key'], 'sk-ant-TestClaudeKey999999');

  // 5. Zero-AI: zero HTTP requests
  const beforeCount = calls.length;
  const zero = await store.discoverModels({ provider: 'zero-ai' });
  assert.equal(zero.ok, true);
  assert.equal(calls.length, beforeCount);
  assert.equal(zero.models[0]?.id, 'deterministic');
});

test('End-to-end runtime switching, adapter routing, exact Q&A attribution, zero secret leakage, and /health 60s probe cache', async () => {
  let fakeNow = 1_700_000_000_000;
  let probeHits = 0;
  const requests: Array<{ url: string; headers: Record<string, string>; body: Record<string, unknown> }> = [];

  const secretGemini = 'AIzaSyEndToEndGeminiSecret8888';
  const secretClaude = 'sk-ant-EndToEndClaudeSecret7777';

  const mockFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    requests.push({ url, headers, body });

    if (url.endsWith('/chat/completions')) {
      const messages = (body.messages as Array<{ content?: string }>) ?? [];
      const userMsg = messages[messages.length - 1]?.content ?? '';
      if (userMsg === 'OK' || userMsg === 'Reply OK') {
        probeHits++;
        return jsonResponse({ choices: [{ message: { content: 'OK' } }] });
      }
      return jsonResponse({
        choices: [{ message: { content: `Live Gemini reply from ${String(body.model)}: rotate exposed AWS key immediately.` } }],
      });
    }

    if (url.endsWith('/messages')) {
      const messages = (body.messages as Array<{ content?: string }>) ?? [];
      const userMsg = messages[messages.length - 1]?.content ?? '';
      if (userMsg === 'OK' || userMsg === 'Reply OK') {
        probeHits++;
        return jsonResponse({ content: [{ type: 'text', text: 'OK' }] });
      }
      return jsonResponse({
        content: [{ type: 'text', text: `Live Claude reply from ${String(body.model)}: verified fix removes literal key.` }],
      });
    }

    return jsonResponse({ error: 'not mocked' }, 404);
  };

  const cfg = loadConfig({ LOCAL_SANDBOX_MODE: 'true' });
  const sg = await createApp(cfg, {
    env: {
      LLM_PROVIDER: 'gemini',
      GEMINI_API_KEY: secretGemini,
      ANTHROPIC_API_KEY: secretClaude,
    },
    fetchFn: mockFetch,
    nowFn: () => fakeNow,
    probeCacheTtlMs: 60_000,
  });

  try {
    // 1. GET /api/llm/config returns sanitized view (zero raw secrets)
    const cfgRes = await sg.app.inject({ method: 'GET', url: '/api/llm/config' });
    assert.equal(cfgRes.statusCode, 200);
    assert.ok(!cfgRes.body.includes(secretGemini));
    assert.ok(!cfgRes.body.includes(secretClaude));
    assert.equal(cfgRes.json().activeProvider, 'gemini');
    assert.equal(cfgRes.json().activeModel, 'gemini-3.5-flash');

    // 2. /health runs 1-token probe and caches for 60s
    const h1 = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(h1.statusCode, 200);
    assert.equal(h1.json().aiStatus, 'healthy');
    assert.equal(h1.json().lastProbe.cached, false);
    assert.equal(probeHits, 1);
    assert.ok(!h1.body.includes(secretGemini));

    fakeNow += 10_000;
    const h2 = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(h2.json().lastProbe.cached, true);
    assert.equal(probeHits, 1, 'second /health within 60s should use cached probe');

    // ?force=true bypasses 60s cache
    const h3 = await sg.app.inject({ method: 'GET', url: '/health?force=true' });
    assert.equal(h3.json().lastProbe.cached, false);
    assert.equal(probeHits, 2, '?force=true must run a fresh probe');

    // Seed a scan cleanly in store for Q&A tests
    const scan = await sg.store.createScan({
      repoFullName: 'acme/runtime-llm-test',
      prNumber: 7,
      headSha: 'abc1234567890',
      headRef: 'feat/auth-key',
      headRepoFullName: 'acme/runtime-llm-test',
      baseRef: 'main',
      prTitle: 'feat(auth): test runtime llm switch',
      prAuthor: 'dev-user',
    });
    const scanId = scan.id;
    await sg.store.updateScan(scanId, {
      status: 'awaiting_approval',
      riskScore: 72,
      severity: 'High',
      findingsCount: 1,
      secretsCount: 1,
    });

    // 3. Ask @spriteguard executes active Gemini model and attributes it accurately
    const askGem = await sg.app.inject({
      method: 'POST',
      url: `/api/scans/${scanId}/ask`,
      payload: { question: 'Is this AWS key exploitable?' },
    });
    assert.equal(askGem.statusCode, 200);
    const gemJson = askGem.json();
    assert.equal(gemJson.engine, 'llm');
    assert.equal(gemJson.provider, 'gemini');
    assert.equal(gemJson.model, 'gemini-3.5-flash');
    assert.equal(gemJson.usedAi, true);
    assert.match(gemJson.answer, /Live Gemini reply from gemini-3\.5-flash/);

    // 4. Switch live to Claude via POST /api/llm/config (no restart, preserves env key, invalidates cache)
    const switchClaude = await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'claude', model: 'claude-sonnet-4-20250514' },
    });
    assert.equal(switchClaude.statusCode, 200);
    assert.equal(switchClaude.json().ok, true);
    assert.equal(switchClaude.json().config.activeProvider, 'claude');
    assert.equal(switchClaude.json().probe.ok, true);
    assert.equal(probeHits, 3, 'switching provider must invalidate cache and run fresh probe');
    assert.ok(!switchClaude.body.includes(secretClaude));

    // Ask @spriteguard now routes to native Anthropic /v1/messages with x-api-key + anthropic-version
    const askClaude = await sg.app.inject({
      method: 'POST',
      url: `/api/scans/${scanId}/ask`,
      payload: { question: 'How do I fix this finding?' },
    });
    assert.equal(askClaude.statusCode, 200);
    const clJson = askClaude.json();
    assert.equal(clJson.engine, 'llm');
    assert.equal(clJson.provider, 'claude');
    assert.equal(clJson.model, 'claude-sonnet-4-20250514');
    assert.equal(clJson.usedAi, true);
    assert.match(clJson.answer, /Live Claude reply from claude-sonnet-4-20250514/);
    const claudeReq = requests.find((r) => r.url === 'https://api.anthropic.com/v1/messages');
    assert.ok(claudeReq, 'expected native /v1/messages request for Claude');
    assert.equal(claudeReq?.headers['x-api-key'], secretClaude);
    assert.equal(claudeReq?.headers['anthropic-version'], '2023-06-01');
    assert.ok(typeof claudeReq?.body.system === 'string', 'Claude request must pass top-level system prompt');

    // 5. Switch to Zero-AI -> zero HTTP requests on both /health and /ask
    const switchZero = await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'zero-ai' },
    });
    assert.equal(switchZero.statusCode, 200);
    const reqCountBeforeZero = requests.length;

    const hZero = await sg.app.inject({ method: 'GET', url: '/health?force=true' });
    assert.equal(hZero.statusCode, 200);
    assert.equal(hZero.json().aiStatus, 'healthy');
    assert.equal(hZero.json().activeProvider, 'zero-ai');
    assert.equal(requests.length, reqCountBeforeZero, 'Zero-AI /health must make zero HTTP requests');

    const askZero = await sg.app.inject({
      method: 'POST',
      url: `/api/scans/${scanId}/ask`,
      payload: { question: 'Why was this flagged?' },
    });
    assert.equal(askZero.statusCode, 200);
    assert.equal(askZero.json().engine, 'deterministic');
    assert.equal(askZero.json().mode, 'zero-ai');
    assert.equal(askZero.json().provider, 'zero-ai');
    assert.equal(askZero.json().model, 'deterministic');
    assert.equal(askZero.json().usedAi, false);
    assert.equal(requests.length, reqCountBeforeZero, 'Zero-AI /ask must make zero HTTP requests');

    // 6. Reject invalid baseUrl
    const badUrl = await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'gemini', baseUrl: 'ftp://evil.example', model: 'gemini-3.5-flash' },
    });
    assert.equal(badUrl.statusCode, 400);
  } finally {
    await sg.close();
  }
});

test('All 5 providers report truthful Degraded health & normalized fallbackReason on failure', async () => {
  const modeByUrl: Record<string, 'gemini404' | 'or401' | 'claude429' | 'localDown'> = {
    gemini: 'gemini404',
    openrouter: 'or401',
    claude: 'claude429',
    local: 'localDown',
  };

  let localAuthHeaderSeen: string | undefined;

  const failingFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    if (url.includes('generativelanguage.googleapis.com')) {
      assert.equal(modeByUrl.gemini, 'gemini404');
      return jsonResponse({ error: { message: 'models/gemini-bad-model is not found' } }, 404);
    }
    if (url.includes('openrouter.ai')) {
      assert.equal(modeByUrl.openrouter, 'or401');
      return jsonResponse({ error: { message: 'Invalid API key sk-or-v1-should-not-leak' } }, 401);
    }
    if (url.includes('api.anthropic.com')) {
      assert.equal(modeByUrl.claude, 'claude429');
      return jsonResponse({ error: { message: 'Rate limit exceeded' } }, 429);
    }
    if (url.includes('localhost:11434')) {
      localAuthHeaderSeen = headers.authorization;
      const err = new TypeError('fetch failed') as TypeError & { cause?: { code: string } };
      err.cause = { code: 'ECONNREFUSED' };
      throw err;
    }
    throw new Error(`Unexpected URL ${url}`);
  };

  const cfg = loadConfig({ LOCAL_SANDBOX_MODE: 'true' });
  const sg = await createApp(cfg, {
    env: {
      GEMINI_API_KEY: 'AIzaSyFailTestKey11111',
      OPENROUTER_API_KEY: 'sk-or-v1-FailTestKey22222',
      ANTHROPIC_API_KEY: 'sk-ant-FailTestKey33333',
    },
    fetchFn: failingFetch,
  });

  try {
    const customRes = await sg.app.inject({
      method: 'POST',
      url: '/api/demo/custom',
      payload: {
        title: 'feat: degraded health verification',
        filename: 'src/key.mjs',
        code: "export const AWS_KEY = 'AKIAIOSFODNN7EXAMPL9';\n",
      },
    });
    const scanId = customRes.json().scan.id as string;

    // 1. Gemini 404
    await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'gemini', model: 'gemini-bad-model', verify: false },
    });
    const askGem = await sg.app.inject({
      method: 'POST',
      url: `/api/scans/${scanId}/ask`,
      payload: { question: 'Why was this flagged?' },
    });
    assert.equal(askGem.json().engine, 'deterministic');
    assert.equal(askGem.json().fallbackReason, 'Gemini 404: model "gemini-bad-model" not found');
    const hGem = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(hGem.json().aiStatus, 'degraded');
    assert.equal(hGem.json().lastProbe.error, 'Gemini 404: model "gemini-bad-model" not found');

    // 2. OpenRouter 401
    await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'openrouter', model: 'google/gemini-3.5-flash', verify: true },
    });
    const hOr = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(hOr.json().aiStatus, 'degraded');
    assert.equal(hOr.json().lastProbe.error, 'OpenRouter 401: invalid or unauthorized API key');
    assert.ok(!hOr.body.includes('sk-or-v1-'));

    // 3. Claude 429
    await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'claude', model: 'claude-sonnet-4-20250514', verify: true },
    });
    const askCl = await sg.app.inject({
      method: 'POST',
      url: `/api/scans/${scanId}/ask`,
      payload: { question: 'Is this exploitable?' },
    });
    assert.equal(askCl.json().engine, 'deterministic');
    assert.equal(askCl.json().fallbackReason, 'Claude 429: rate limit or quota exceeded');
    const hCl = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(hCl.json().aiStatus, 'degraded');
    assert.equal(hCl.json().lastProbe.error, 'Claude 429: rate limit or quota exceeded');

    // 4. Local Ollama ECONNREFUSED (also verifies Authorization header is omitted when no local key is set)
    await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'local', baseUrl: 'http://localhost:11434/v1', model: 'qwen2.5-coder', verify: true },
    });
    assert.equal(localAuthHeaderSeen, undefined, 'Local Ollama requests must omit Authorization header when no key is set');
    const hLoc = await sg.app.inject({ method: 'GET', url: '/health' });
    assert.equal(hLoc.json().aiStatus, 'degraded');
    assert.equal(hLoc.json().lastProbe.error, 'Local: Ollama unreachable at localhost:11434');

    // 5. Zero-AI -> Healthy with 0 network calls
    await sg.app.inject({
      method: 'POST',
      url: '/api/llm/config',
      payload: { provider: 'zero-ai' },
    });
    const hZero = await sg.app.inject({ method: 'GET', url: '/health?force=true' });
    assert.equal(hZero.json().aiStatus, 'healthy');
    assert.equal(hZero.json().status, 'ok');
    assert.equal(hZero.json().aiHealthMessage, 'Zero-AI deterministic mode active');
  } finally {
    await sg.close();
  }
});
