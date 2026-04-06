# IaC Sentinel

> AI-powered Infrastructure-as-Code security scanner — powered by Auth0 Token Vault, Grok-3-mini, DeepSeek, and Checkov.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-iac--sentinel-green?style=for-the-badge)](http://iac-sentinel-prod.eba-wxndpc2q.us-east-1.elasticbeanstalk.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by Auth0](https://img.shields.io/badge/Powered%20by-Auth0%20Token%20Vault-orange)](https://auth0.com/docs/secure/tokens)
[![Deployed on AWS](https://img.shields.io/badge/Deployed%20on-AWS%20Elastic%20Beanstalk-orange?logo=amazonaws)](https://aws.amazon.com/elasticbeanstalk/)

Point IaC Sentinel at any GitHub repository. In ~60 seconds you get severity-rated findings, plain-English risk explanations, and complete corrected Terraform files — all without your GitHub token ever touching the agent.

---

## How It Works

```
Browser (Auth0 login)
        │
        ▼
FastAPI backend  ──  Auth0 Token Vault  ──►  GitHub API
        │
        ▼
LangGraph ReAct Agent (Grok-3-mini orchestrator)
        │
        ├── fetch_iac_files      →  Token Vault exchanges refresh token
        │                            for short-lived GitHub token on demand
        │
        ├── scan_iac_security    →  Checkov static analysis
        │                            + DeepSeek structured findings & fixes
        │
        └── preview_fix_diff     →  Copy-ready corrected files
```

**The security model in one sentence:** Auth0 Token Vault holds your GitHub OAuth token. The agent never sees it — it requests a short-lived scoped token at runtime, uses it once, and discards it.

---

## Features

- **Token Vault integration** — GitHub credentials stored in Auth0, exchanged on demand via federated token grant. No PATs, no environment variables holding secrets.
- **Hybrid analysis** — Checkov catches rule-based misconfigurations in milliseconds. DeepSeek explains *why* each finding is dangerous and generates context-aware fixed files.
- **Structured output** — findings parsed into `[High/Medium/Low]` severity cards with risk context and one-line fix guidance. High-severity issues come with complete corrected files, not just diffs.
- **Live audit trail** — every Token Vault exchange, file fetch, and scan event is logged and visible in the UI.
- **Production-hardened** — HMAC-signed job IDs, PII redaction on all LLM input/output, rate limiting, CSP/HSTS headers, async concurrency controls.

---

## Quick Start

### Prerequisites

- Python 3.12+
- [Checkov](https://www.checkov.io/) installed and on `PATH`
- Auth0 tenant with GitHub as a connected provider
- xAI API key (Grok-3-mini)
- DeepSeek API key

### Local Setup

```bash
git clone https://github.com/nurusyda/IaC-Sentinel.git
cd IaC-Sentinel

pip install -r requirements.txt

cp .env.example .env
# Fill in all required variables (see below)

uvicorn application:app --host 127.0.0.1 --port 8000 --reload
```

### Docker

```bash
docker build -t iac-sentinel .
docker run -p 8080:8080 --env-file .env iac-sentinel
```

---

## Environment Variables

| Variable | Description | Required |
|---|---|---|
| `SESSION_SECRET_KEY` | Secret for signing session cookies and job IDs | ✅ |
| `AUTH0_DOMAIN` | Your Auth0 tenant domain (e.g. `dev-xxx.us.auth0.com`) | ✅ |
| `AUTH0_CLIENT_ID` | Auth0 application client ID | ✅ |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | ✅ |
| `AUTH0_GITHUB_AUTHORIZE_URL` | Auth0 authorize URL for GitHub connect | ✅ |
| `REDIRECT_URI` | OAuth callback URL (e.g. `https://yourdomain.com/callback`) | ✅ |
| `XAI_API_KEY` | xAI API key for Grok-3-mini | ✅ |
| `DEEPSEEK_API_KEY` | DeepSeek API key | ✅ |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | ❌ |
| `REDIS_URL` | Redis connection URL for job storage (falls back to in-memory) | ❌ |
| `ENVIRONMENT` | Set to `production` to enable HSTS and strict cookie flags | ❌ |
| `FORCE_HTTPS` | Set to `true` to mark session cookie as Secure | ❌ |
| `STREAM_TIMEOUT_SECONDS` | SSE stream timeout (default: 300) | ❌ |

---

## Auth0 Setup

1. Create an Auth0 application (Regular Web Application)
2. Add your `REDIRECT_URI` to **Allowed Callback URLs**
3. Enable **GitHub** as a social connection
4. Enable **Token Vault** for the GitHub connection in Auth0 dashboard
5. Enable **offline_access** scope so refresh tokens are issued
6. Set the **My Account API** audience to `https://{your-domain}/me/`

The agent uses Auth0's federated connection token-exchange grant to retrieve GitHub tokens at runtime:

```json
{
  "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
  "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
  "connection": "github"
}
```

---

## Deploying to AWS Elastic Beanstalk

```bash
# Configure once
export AWS_ACCOUNT_ID=your-account-id
export AWS_REGION=us-east-1

# Build, push to ECR, and deploy
./deploy.sh
```

The deploy script handles: Docker build → ECR push → EB application version → environment update.

Set all environment variables in the EB console under **Configuration → Environment properties** before first deploy.

---

## Project Structure

```
IaC-Sentinel/
├── application.py          # FastAPI app, agent, all endpoints
├── index.html              # Single-file SPA frontend
├── requirements.txt        # Python dependencies
├── Dockerfile              # python:3.12-slim container
├── Dockerrun.aws.json      # EB Docker configuration
├── deploy.sh               # ECR + EB deploy pipeline
└── .ebextensions/
    ├── 01-env-validation.config   # Startup env var check
    └── 02-healthcheck.config      # ALB health check settings
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Backend framework | FastAPI, Starlette, Uvicorn |
| Auth & identity | Auth0 Token Vault, `auth0-ai-langchain`, OAuth 2.0 PKCE |
| Agent orchestration | LangGraph (`create_react_agent`), LangChain Core |
| Orchestrator LLM | xAI Grok-3-mini |
| Analysis LLM | DeepSeek-V3 (`deepseek-chat`) |
| Static IaC scanning | Checkov 3.2.x |
| GitHub integration | PyGithub (via Token Vault) |
| Session management | Starlette SessionMiddleware + itsdangerous |
| Rate limiting | SlowAPI |
| Job storage | Redis (production) / in-memory fallback |
| Frontend | Vanilla HTML/CSS/JS — single file, no build step |
| Cloud deployment | AWS Elastic Beanstalk, Amazon ECR |

---

## Security Notes

- GitHub tokens are never stored — fetched on demand, used once, discarded
- All LLM input and output passes through a PII redactor (phone, SSN, email, AWS keys, API secrets)
- Job IDs are HMAC-signed and bound to the session that created them
- Checkov runs in a sandboxed temp directory with path traversal prevention
- Content Security Policy, HSTS, X-Frame-Options, and Referrer-Policy headers on all responses

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built for the **Auth0 Authorized to Act Hackathon 2026**

*The agent borrows your credentials. It never owns them.*

</div>
