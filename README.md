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

## 4. Production Deployment Guide

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

## 5. Pull Request Commands

Once SpriteGuard posts its Security Audit Report on a PR:
- **`/spriteguard approve`** — Maintainer-only (`admin` or `maintain`, configurable via `APPROVER_MIN_PERMISSION`). Wakes the sleeping Sprite, cross-checks the verified patch `diff_sha256`, commits the verified patch via the GitHub Write Connector, and destroys the Sprite.
- **`@spriteguard <question>`** — Queries Claude Opus grounded in the stored scan report, egress telemetry, patch verification, and pgvector past incidents, replying directly on the PR.
- **`/spriteguard rescan`** — Spins up a fresh isolated Sprite and re-runs the full 3-layer audit.

---

## 6. HTTP Endpoints & Project Structure

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
