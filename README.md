<p align="center">
  <img src="assets/spriteguard-logo.svg" alt="SpriteGuard Logo" width="84" height="84" />
</p>

<h1 align="center">SpriteGuard</h1>

**SpriteGuard** is an autonomous, zero-trust Pull Request security engineer built for the **Fly.io Hacksgiving 2026** hackathon. It executes untrusted PR dependencies, builds, and test suites inside hardware-isolated **Fly.io Sprites**, runs a **3-Layer Dynamic Security Audit** backed by **Claude Opus** (or any OpenAI-compatible LLM) and **Neon pgvector** semantic memory, autonomously generates and verifies remediation patches inside the Sprite, hibernates the Sprite at zero compute cost while awaiting human approval, and commits verified fixes strictly through a separated **GitHub Write Connector**.

---

## 1. Zero-Trust Split-Connector Architecture

Untrusted PR code never touches GitHub write credentials, and raw secrets never reach the LLM:

```
GitHub PR / Comment Webhook (HMAC SHA-256 verified)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Trusted Orchestrator (Fastify + Node 22 + Neon Postgres / pgvector)     │
│                                                                         │
│  Read-Only GitHub Connector ──► Isolated Fly.io Sprite (NO GH tokens)   │
│  (contents:read, pr:read)       ├─ Layer A: Secret & .env Scanner       │
│                                 ├─ Layer B: Egress Hook & Canary Probe  │
│                                 └─ Patch Verification + Sleep/Wake      │
│                                                                         │
│  RedactionVault ──► Layer C: Claude Opus 4.6 + Neon pgvector Memory     │
│                                                                         │
│  Maintainer `/spriteguard approve` ──► Wake Sprite & Cross-Verify SHA256│
│                                         ▼                               │
│                                  Trusted Publisher                      │
│                                  (GitHub Write Connector)               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Security Invariants
1. **No GitHub tokens inside Sprites:** Public repositories clone unauthenticated inside the Sprite; private repositories are downloaded as tarballs by the trusted orchestrator over `ReadOnlyGitHubConnector` and streamed into the Sprite.
2. **Split GitHub Connectors:** `ReadOnlyGitHubConnector` and `GitHubWriteConnector` (`TrustedPublisher`) are physically separated classes using down-scoped GitHub App installation tokens (or strictly distinct `GITHUB_READ_TOKEN` and `GITHUB_WRITE_TOKEN` PATs).
3. **In-Memory Redaction Vault:** Raw secret literals detected by Layer A/B never enter Claude prompts and are never persisted to Neon Postgres. Only redacted placeholders and SHA-256 fingerprints leave the scanner.
4. **Verified Patch Integrity Gate:** Autonomous patches are saved in Postgres (`audit_patches`) with their `diff_sha256`. On `/spriteguard approve`, the orchestrator verifies maintainer permissions, verifies the PR `headSha` has not moved, wakes the sleeping Sprite, cross-checks `verified-patch.json` against Postgres, and pushes strictly the trusted `PatchFile[]` stored in Postgres—never arbitrary files from the untrusted Sprite filesystem.

---

## 2. Three-Layer Audit Pipeline

- **Layer A — Static & Build Secret Scanner (`src/scanner/secretScanner.ts`):**
  Scans PR diffs, entire PR commit history (catching secrets added and deleted in earlier commits), committed `.env*` files, and build outputs (`dist/`, `build/`, `.next/`, `out/`) for AWS, Stripe, Anthropic, OpenAI, GitHub, Slack, Google keys, JWTs, private key blocks, credentialed DB URLs, and Shannon high-entropy strings.
- **Layer B — Runtime & Network Egress Probe (`src/scanner/egressProbe.ts`):**
  Applies Sprite network egress allowlists and installs Node (`NODE_OPTIONS`) + Python (`PYTHONPATH/sitecustomize.py`) preload hooks alongside synthetic **canary secrets** (`AWS_ACCESS_KEY_ID`, `SPRITEGUARD_CANARY_KEY`, `SPRITEGUARD_CANARY_TOKEN`). Executes dependency installation, build scripts, and tests, capturing every DNS lookup, TCP socket connect, HTTP(S)/`fetch` call, stdout/stderr leak, and active canary exfiltration.
- **Layer C — Claude Opus Auditor & Neon pgvector Memory (`src/scanner/opusAuditor.ts`, `src/db/client.ts`):**
  Queries `security_findings` in Neon Postgres via pgvector HNSW cosine similarity search for recurring vulnerability patterns in the repository, sends the redacted diff + Layer A/B evidence + past incidents to **Claude Opus** (`claude-opus-4-6`), computes a 0–100 Risk Score, generates a remediation patch, restores the pre-audit Sprite checkpoint, applies and re-verifies the patch + full test suite, and puts the Sprite to sleep (`checkpoint` + scale to zero).

---

## 3. Quickstart — Local Sandbox Mode (No Cloud Keys Required)

Test the entire pipeline—static secret scan, live runtime egress hooking, canary detection, autonomous patch generation & test verification, live dark-mode dashboard, `@spriteguard` Q&A, and `/spriteguard approve`—in seconds locally:

```bash
cp .env.example .env
npm install
npm run typecheck
npm test
```

### Run the Interactive CLI End-to-End Demo
```bash
npm run demo
```

### Start the Server & Live Dark-Mode Dashboard
```bash
npm run dev
```
Open **http://localhost:8080** in your browser. In `LOCAL_SANDBOX_MODE=true`, the dashboard displays a **Run Demo PR Audit** control panel, KPI telemetry cards, expandable findings/egress/diff/Markdown/JSON views, inline **`@spriteguard`** Q&A, and one-click **`/spriteguard approve`**.

> **Note:** `LOCAL_SANDBOX_MODE=true` uses `LocalSandboxDriver` (a local scratch directory without VM hardware isolation) solely for local fixtures (`LOCAL_ALLOW_UNTRUSTED_EXEC=false` by default skips executing arbitrary external PRs locally).

---

## 4. Configuring AI Providers (Cloud, Open-Source, Local Ollama, or Zero-AI)

SpriteGuard is provider-agnostic and selects its Layer C AI engine using strict environment variable precedence:

1. **`LLM_BASE_URL` is set** → routes to any OpenAI-compatible `/chat/completions` endpoint (Local Ollama, OpenRouter, Google Gemini, Groq, OpenAI, vLLM, etc.).
2. **Else `ANTHROPIC_API_KEY` is set** → uses the native Anthropic SDK directly.
3. **Else (both unset)** → runs in **Zero-AI** mode using Layer A/B deterministic scanners and the built-in heuristic auditor, patcher, and grounded Q&A fallback.

> **Secret-Redaction Privacy Guarantee (`RedactionVault`):** Before any diff, runtime output, or Q&A context leaves the server, SpriteGuard's in-memory `RedactionVault` scans and replaces detected secret literals with opaque `[REDACTED_SECRET_N:...]` placeholders. Raw credentials are never sent to external LLM providers and never persisted to Postgres. For zero outbound LLM traffic, use **Local Ollama** or **Zero-AI** mode.

### Option 1 — Local Ollama (Fully Local Privacy)
```dotenv
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=qwen2.5-coder
```
`LLM_API_KEY=ollama` serves as a placeholder key so OpenAI-compatible clients do not reject empty keys.

> **Fly.io `localhost` caveat:** `http://localhost:11434/v1` works when SpriteGuard runs locally on your machine alongside Ollama. When deployed on **Fly.io**, `localhost` refers to the Fly VM itself—use a tunnel or hosted OpenAI-compatible endpoint instead.

### Option 2 — OpenRouter (Open-Source & Multi-Model Routing)
```dotenv
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=your-key
LLM_MODEL=qwen/qwen-2.5-coder-32b-instruct
```

### Option 3 — Google Gemini (OpenAI-Compatible Endpoint)
```dotenv
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
LLM_API_KEY=your-key
LLM_MODEL=gemini-2.5-flash
```

### Option 4 — Anthropic Claude (Native SDK)
Leave `LLM_BASE_URL` unset and configure:
```dotenv
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-6
```
Current Anthropic model IDs: `claude-sonnet-4-6` and `claude-haiku-4-5` are fastest for PR audits, while `claude-opus-4-6` provides the deepest security reasoning.

### Option 5 — Zero-AI Deterministic Mode
Leave both `LLM_BASE_URL` and `ANTHROPIC_API_KEY` unset:
```dotenv
LLM_BASE_URL=
ANTHROPIC_API_KEY=
```
SpriteGuard runs 100% deterministically on Layer A static/history/dotenv secret scanning, Layer B runtime egress & canary traps, deterministic patch generation/verification, and grounded Q&A fallback with zero external LLM calls.

### Self-Hosting on Fly.io (`fly.toml` `[env]` vs `fly secrets`)
Keep non-secret provider routing in `fly.toml` under `[env]` so model switches are version-controlled, and store API keys strictly as encrypted Fly secrets:

```toml
# fly.toml
[env]
  LLM_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
  LLM_MODEL = "gemini-2.5-flash"
```

```bash
fly secrets set -a spriteguard LLM_API_KEY="your-key"
```

*(For native Claude on Fly.io, omit `LLM_BASE_URL` from `[env]`, set `ANTHROPIC_MODEL = "claude-sonnet-4-6"`, and run `fly secrets set -a spriteguard ANTHROPIC_API_KEY="sk-ant-..."`.)*

---

## 5. Production Deployment Guide

### A. Neon Postgres + pgvector Setup
1. Create a Neon project and copy your pooled connection string.
2. Enable `pgvector` and run the schema migration:
   ```bash
   DATABASE_URL="postgres://..." npm run db:migrate
   ```
   This applies `src/db/schema.sql`, creating the `pgcrypto` and `vector` extensions along with `pr_scans`, `security_findings` (with a 1024-dim HNSW cosine index), and `audit_patches`.

### B. GitHub App / Split Connectors & Webhook Setup
Create a **GitHub App** (recommended) with:
- **Repository permissions:**
  - `Contents`: **Read & write** (SpriteGuard down-scopes read tokens to `contents:read` for audits and only requests `contents:write` in `TrustedPublisher`)
  - `Pull requests`: **Read & write**
  - `Issues`: **Read & write** (required for PR comment commands & reactions)
  - `Metadata`: **Read-only**
- **Webhook URL:** `https://<your-app>.fly.dev/webhook`
- **Webhook Secret:** strong random secret matching `GITHUB_WEBHOOK_SECRET`
- **Subscribed events:** `Pull request`, `Issue comment`

*(Alternatively, set two strictly distinct fine-grained PATs: `GITHUB_READ_TOKEN` with Read-only Contents/PRs and `GITHUB_WRITE_TOKEN` with Read+Write Contents/PRs/Issues.)*

### C. Fly.io Secrets & Deployment
1. Launch and configure secrets on Fly.io:
   ```bash
   fly launch --no-deploy
   fly secrets set \
     LOCAL_SANDBOX_MODE=false \
     ANTHROPIC_API_KEY="sk-ant-..." \
     DATABASE_URL="postgres://..." \
     SPRITES_TOKEN="your-sprites-token" \
     GITHUB_WEBHOOK_SECRET="your-webhook-secret" \
     GITHUB_APP_ID="123456" \
     GITHUB_APP_PRIVATE_KEY="$(base64 -i private-key.pem | tr -d '\n')" \
     PUBLIC_URL="https://spriteguard.fly.dev"
   ```
2. Deploy:
   ```bash
   fly deploy
   ```
3. Verify health:
   ```bash
   curl https://spriteguard.fly.dev/health
   ```

---

## 6. Pull Request Commands

Once SpriteGuard posts its Security Audit Report on a PR:
- **`/spriteguard approve`** — Maintainer-only (`admin` or `maintain`, configurable via `APPROVER_MIN_PERMISSION`). Wakes the sleeping Sprite, cross-checks the verified patch `diff_sha256`, commits the verified patch via the GitHub Write Connector, and destroys the Sprite.
- **`@spriteguard <question>`** — Queries Claude Opus grounded in the stored scan report, egress telemetry, patch verification, and pgvector past incidents, replying directly on the PR.
- **`/spriteguard rescan`** — Spins up a fresh isolated Sprite and re-runs the full 3-layer audit.

---

## 7. HTTP Endpoints & Project Structure

| Endpoint | Description |
| --- | --- |
| `GET /` | Live dark-mode security operations dashboard |
| `GET /health` | Health check (`dbHealthy`, active driver, GitHub connector mode, model) |
| `POST /webhook` | HMAC SHA-256 verified GitHub webhook receiver |
| `GET /api/scans` | Dashboard KPIs + recent PR scans (optional `Authorization: Bearer $DASHBOARD_TOKEN`) |
| `GET /api/scans/:id` | Detailed scan, verified patch record, and timeline |

```text
spriteguard/
├── src/
│   ├── index.ts                  # Fastify server (/, /health, /webhook, /api/scans)
│   ├── config.ts                 # Zod-validated configuration & zero-trust guards
│   ├── types.ts                  # Shared domain types
│   ├── logger.ts                 # Structured redacting Pino logger
│   ├── orchestrator.ts           # Trusted Orchestrator & TrustedPublisher
│   ├── demoFixtures.ts           # Self-contained vulnerable & clean PR fixtures
│   ├── db/
│   │   ├── schema.sql            # Postgres + pgvector HNSW schema
│   │   └── client.ts             # Neon Postgres + pgvector & InMemory store
│   ├── fly/
│   │   ├── spriteManager.ts      # Fly Sprites SDK lifecycle + local sandbox driver
│   │   └── githubConnector.ts    # Split Read-Only & Write connectors + local simulator
│   ├── scanner/
│   │   ├── secretScanner.ts      # Layer A: Regex + Shannon entropy + RedactionVault
│   │   ├── egressProbe.ts        # Layer B: Node/Python preload hooks + canary traps
│   │   └── opusAuditor.ts        # Layer C: Claude Opus auditor, patcher, verifier & Q&A
│   ├── github/
│   │   ├── webhookHandler.ts     # HMAC verification & PR/comment event router
│   │   └── reportFormatter.ts    # GitHub-Flavored Markdown audit reports
│   └── ui/
│       └── dashboard.html        # Single-file dark-mode live status dashboard
├── scripts/
│   ├── copy-assets.mjs
│   ├── demo.ts
│   └── migrate.ts
├── test/
│   └── spriteguard.test.ts
├── Dockerfile
├── fly.toml
├── .env.example
└── package.json
```

---

## Post-Hackathon Roadmap

### 1. Product Vision — From Solo PR Reviewer to Autonomous AppSec Platform

**Find. Fix. Verify.** — *One engine, multiple experiences.*

SpriteGuard's core zero-trust microVM audit, patch, and verification engine scales cleanly across four audiences without sacrificing developer speed or split-connector safety:

| Audience | Core Need | SpriteGuard Experience |
| --- | --- | --- |
| **Individual Developers** | Fast, zero-friction PR security checks | Instant isolated PR audits, copyable fix prompts, local Ollama / Zero-AI privacy |
| **Development Teams** | Shared triage and safe patch approvals | Team ownership, `CODEOWNERS` quorum approvals, finding deduplication |
| **Advanced Engineering Teams** | Policy enforcement and AI-era guardrails | CI/CD merge gates, SBOM/supply-chain checks, SARIF/CLI/Linear/Slack, AI Change Security Review |
| **Security Organizations** | Fleet-wide visibility and governance | Multi-repo risk campaigns, SLAs, time-bound risk exceptions, audit trails |

---

### 2. Five-Phase Product & Engineering Roadmap

1. **Phase 1 — Developer Experience *(Shipped)***
   - Zero-config PR auditing inside ephemeral hardware-isolated Firecracker Sprites.
   - Universal AI provider support (Anthropic Claude, OpenRouter, Gemini, Local Ollama) with `RedactionVault` scrubbing and deterministic Zero-AI fallback.
   - Copyable fix prompts, grounded `@spriteguard` Q&A drawer, and a keyboard-first operations dashboard.

2. **Phase 2 — Team Collaboration & Security Operations**
   - Organizations, team workspaces, and `CODEOWNERS` quorum approvals (`N` maintainer sign-offs required before `/spriteguard approve` commits fixes).
   - Cross-revision finding deduplication and full ownership lifecycle tracking (*Detected → Triaged → Assigned → Remediation → Verification → Closed*).

3. **Phase 3 — Advanced Engineering & AI Security**
   - Configurable CI/CD merge gates (`Block` / `Require Approval` / `Warn`).
   - SBOM generation and transitive dependency / supply-chain analysis.
   - Custom org-wide egress allowlists and reusable policy profiles.
   - SARIF exports, CLI, REST API, Slack, and Linear integrations.
   - **AI Change Security Review** to validate AI-generated diffs and agent tool permissions before merge.

4. **Phase 4 — Enterprise Risk & Governance**
   - Multi-repo fleet visibility and cross-repository security campaigns.
   - Remediation SLA tracking, risk exception management with automatic expiry, and immutable compliance audit trails.

5. **Phase 5 — Specialized Multi-Sprite Orchestration**
   - Evolve from a single audit Sprite into specialized, policy-bound microVM workers sharing a unified evidence and permissions framework:
     - **Secret Sprite** — deep static, git-history, and build-artifact credential scanning.
     - **Supply Sprite** — lockfile, SBOM, and install-script supply-chain isolation.
     - **Egress Sprite** — runtime DNS/TCP/HTTP capture and canary exfiltration traps.
     - **Patch Sprite** — autonomous remediation drafting and test-suite re-verification.
     - **Cloud Sprite** — IaC, IAM, and deployment manifest security validation.
     - **Pipeline Sprite** — CI/CD workflow and GitHub Actions permission auditing.

---

### 3. Frontend Maintainability

- **Split `src/ui/dashboard.html`:** Following the hackathon submission freeze, refactor the single-file dashboard into modular UI components, isolated stylesheets, and typed client modules for cleaner testing, code review, and long-term iteration.
