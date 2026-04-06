import asyncio
import os
import shutil
import logging
import sys
import subprocess
import json
import secrets
import httpx
import pathlib
import re
import hmac
import hashlib
import time
from collections import deque, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any, List

# ── 1. LOAD ENV FIRST ─────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ── 2. LOGGING ────────────────────────────────────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── 3. AUTH0 AI SDK ───────────────────────────────────────────────────────
MOCK_AUTH0 = os.environ.get("MOCK_AUTH0", "false").lower() == "true"

try:
    from auth0_ai_langchain.auth0_ai import Auth0AI
    try:
        from auth0_ai_langchain.exceptions import ConsentRequiredError
    except ImportError:
        try:
            from auth0_ai.exceptions import ConsentRequiredError
        except ImportError:
            class ConsentRequiredError(Exception):
                def __init__(self, connection: str, authorization_url: str = None):
                    self.connection = connection
                    self.authorization_url = authorization_url
    _AUTH0_SDK_AVAILABLE = True
    logger.info("AUTH0 SDK LOADED: Token Vault is active.")
except ImportError as e:
    if not MOCK_AUTH0:
        raise RuntimeError("Auth0 SDK not found and MOCK_AUTH0=false. Aborting startup.") from e
    _AUTH0_SDK_AVAILABLE = False
    logger.warning(f"Auth0 SDK failed to load (mock-mode): {e}")

    class ConsentRequiredError(Exception):
        def __init__(self, connection: str, authorization_url: str = None):
            self.connection = connection
            self.authorization_url = authorization_url

    class Auth0AI:
        pass

auth0_ai = Auth0AI()

# ── 4. CORE IMPORTS ───────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, field_validator
from github import Github, GithubException
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage
from langchain_core.runnables import ensure_config
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

try:
    import redis.asyncio as aioredis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

# ── 5. AUDIT LOG ──────────────────────────────────────────────────────────
AUDIT_LOG: deque = deque(maxlen=1000)

def log_audit_event(action: str, details: str = "", target: str = "Internal"):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details,
        "target": target,
        "source": "Token Vault",
    }
    AUDIT_LOG.append(event)
    logger.info(f"AUDIT: {event}")

# ── 6. CONFIG ─────────────────────────────────────────────────────────────
MAX_IAC_FILES          = 15
MAX_CONCURRENT_JOBS    = 10
MAX_STORED_JOBS        = 100
MAX_LLM_CONTENT_BYTES  = 400_000
MAX_USER_MESSAGE_BYTES = 2_000

AUTH0_DOMAIN        = os.environ.get("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID     = os.environ.get("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", "")

if not AUTH0_DOMAIN:
    logger.warning("AUTH0_DOMAIN is empty — the constructed authorize URL will be malformed.")

AUTH0_URL = os.environ.get("AUTH0_GITHUB_AUTHORIZE_URL")
if not AUTH0_URL and os.environ.get("ENVIRONMENT") == "production":
    raise RuntimeError("AUTH0_GITHUB_AUTHORIZE_URL is required in production")
AUTH0_URL = AUTH0_URL or f"https://{AUTH0_DOMAIN}/authorize"

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY:
    raise RuntimeError("SESSION_SECRET_KEY environment variable is required")

REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback")

ALLOWED_ORIGINS_RAW = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000",
)
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_RAW.split(",")]

DEFAULT_ALLOWED_URIS = (
    f"{REDIRECT_URI},http://127.0.0.1:8000/callback,http://localhost:8000/callback"
)
ALLOWED_REDIRECT_URIS = set(
    u.strip()
    for u in os.environ.get("ALLOWED_REDIRECT_URIS", DEFAULT_ALLOWED_URIS).split(",")
)

STREAM_TIMEOUT_SECONDS = int(os.environ.get("STREAM_TIMEOUT_SECONDS", "300"))

# ── 7. APP INIT ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
_sessions_lock = asyncio.Lock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IaC Sentinel starting up with Auth0 Token Vault...")
    purge_task = asyncio.create_task(_periodic_session_purge())
    yield
    purge_task.cancel()
    try:
        await purge_task
    except asyncio.CancelledError:
        pass
    if redis_client is not None:
        await redis_client.aclose()
    logger.info("IaC Sentinel shutting down.")

async def _periodic_session_purge():
    while True:
        await asyncio.sleep(600)
        await purge_expired_sessions()

app = FastAPI(
    title="IaC Sentinel",
    description="AI-powered IaC security scanner using Auth0 Token Vault.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="iac_sentinel_session",
    https_only=os.environ.get("ENVIRONMENT", "development") == "production",
    max_age=3600 * 8,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if os.environ.get("ENVIRONMENT") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src https://fonts.gstatic.com data:; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
else:
    logger.warning("static/ directory not found — /static/* routes will 404")

application = app

# ── 7.5 JOB STORE ────────────────────────────────────────────────────────
jobs_memory: OrderedDict = OrderedDict()

REDIS_URL = os.environ.get("REDIS_URL")
if _REDIS_AVAILABLE and REDIS_URL:
    redis_client = aioredis.from_url(REDIS_URL)
    logger.info("Connected to Redis for job storage.")
else:
    redis_client = None
    logger.info("Using in-memory job storage (Redis not configured).")

async def store_job(job_id: str, data: Dict[str, Any]):
    if redis_client:
        await redis_client.setex(f"job:{job_id}", 3600, json.dumps(data))
    else:
        jobs_memory[job_id] = data
        while len(jobs_memory) > MAX_STORED_JOBS:
            jobs_memory.popitem(last=False)

async def get_job(job_id: str) -> dict | None:
    if redis_client:
        raw = await redis_client.get(f"job:{job_id}")
        return json.loads(raw) if raw else None
    return jobs_memory.get(job_id)

async def update_job(job_id: str, new_data: dict):
    job = await get_job(job_id) or {}
    job.update(new_data)
    await store_job(job_id, job)

# ── JOB ID HMAC ───────────────────────────────────────────────────────────
def make_job_id(session_id: str) -> str:
    rand = secrets.token_urlsafe(16)
    mac  = hmac.new(
        SESSION_SECRET_KEY.encode(),
        f"{session_id}:{rand}".encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"{rand}.{mac}"

def verify_job_id(job_id: str, session_id: str) -> bool:
    if not job_id or "." not in job_id:
        return False
    try:
        rand, mac = job_id.split(".", 1)
        expected = hmac.new(
            SESSION_SECRET_KEY.encode(),
            f"{session_id}:{rand}".encode(),
            hashlib.sha256,
        ).hexdigest()[:16]
        return hmac.compare_digest(mac, expected)
    except Exception:
        return False

# ── CONCURRENT JOBS COUNTER ───────────────────────────────────────────────
_active_jobs_count = 0
_active_jobs_lock  = asyncio.Lock()

async def _increment_jobs() -> bool:
    global _active_jobs_count
    async with _active_jobs_lock:
        if _active_jobs_count >= MAX_CONCURRENT_JOBS:
            return False
        _active_jobs_count += 1
        return True

async def _decrement_jobs():
    global _active_jobs_count
    async with _active_jobs_lock:
        _active_jobs_count = max(0, _active_jobs_count - 1)

# ── SESSION STORE ─────────────────────────────────────────────────────────
sessions: OrderedDict = OrderedDict()
MAX_STORED_SESSIONS = 500
SESSION_TTL         = 3600 * 8

def _session_create_sync(refresh_token: str) -> str:
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {"refresh_token": refresh_token, "created_at": time.time()}
    while len(sessions) > MAX_STORED_SESSIONS:
        sessions.popitem(last=False)
        log_audit_event("SESSION_EVICTED", f"Oldest session evicted (cap={MAX_STORED_SESSIONS})")
    return session_id

async def create_session(refresh_token: str) -> str:
    async with _sessions_lock:
        return _session_create_sync(refresh_token)

async def get_session(session_id: str) -> dict | None:
    async with _sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return None
        if time.time() - s["created_at"] > SESSION_TTL:
            sessions.pop(session_id, None)
            return None
        return s

async def delete_session(session_id: str):
    async with _sessions_lock:
        sessions.pop(session_id, None)

async def purge_expired_sessions():
    now = time.time()
    async with _sessions_lock:
        expired = [sid for sid, s in sessions.items() if now - s["created_at"] > SESSION_TTL]
        for sid in expired:
            sessions.pop(sid, None)
    if expired:
        logger.info(f"Purged {len(expired)} expired sessions.")

# ── SENSITIVE STRING ──────────────────────────────────────────────────────
class SensitiveStr(str):
    def __repr__(self) -> str: return "'[REDACTED]'"
    def __str__(self)  -> str: return "[REDACTED]"
    def reveal(self)   -> str: return str.__str__(self)

# ── RETRY HELPER ──────────────────────────────────────────────────────────
async def _with_retry(coro_fn, retries: int = 2, backoff: float = 1.0):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return await coro_fn()
        except HTTPException as e:
            if e.status_code == 502 and attempt < retries:
                last_exc = e
                await asyncio.sleep(backoff * (2 ** attempt))
                continue
            raise
    raise last_exc

# ── 8. TOOL SCHEMAS ───────────────────────────────────────────────────────
class FetchIacFilesArgs(BaseModel):
    repo_owner: str = Field(description="GitHub repository owner")
    repo_name:  str = Field(description="GitHub repository name")

class ScanIacArgs(BaseModel):
    code: str = Field(
        description=(
            "The EXACT raw code retrieved from the fetch_iac_files tool. "
            "YOU MUST RUN fetch_iac_files FIRST. "
            "DO NOT guess, hallucinate, or make up code."
        )
    )

class FileChange(BaseModel):
    path:    str = Field(description="File path relative to repo root")
    content: str = Field(description="New file content with security fixes applied")

class ProposeFixArgs(BaseModel):
    repo_owner:      str
    repo_name:       str
    branch:          str
    title:           str
    body:            str
    files_to_change: List[FileChange]

# ── 9. AUTH DEPENDENCIES ──────────────────────────────────────────────────
async def get_current_user(request: Request):
    session_id = request.session.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    session = await get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired. Please re-authenticate.")
    return session

async def get_my_account_token(request: Request) -> str:
    session_id = request.session.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Refresh token missing.")
    session = await get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired. Please re-authenticate.")
    refresh_token = SensitiveStr(session.get("refresh_token", ""))
    if not refresh_token.reveal():
        raise HTTPException(status_code=401, detail="Refresh token missing. Please re-authenticate.")

    async def _exchange():
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"https://{AUTH0_DOMAIN}/oauth/token",
                json={
                    "grant_type":    "refresh_token",
                    "client_id":     AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "refresh_token": refresh_token.reveal(),
                    "audience":      f"https://{AUTH0_DOMAIN}/me/",
                    "scope": (
                        "openid profile offline_access "
                        "create:me:connected_accounts read:me:connected_accounts "
                        "delete:me:connected_accounts"
                    ),
                },
            )
            if response.status_code in (400, 401, 403):
                raise HTTPException(status_code=401, detail="Session expired. Please re-authenticate.")
            if response.status_code >= 500:
                raise HTTPException(status_code=502, detail="Auth provider unavailable.")
            try:
                data = response.json()
            except ValueError as exc:
                raise HTTPException(status_code=502, detail="Invalid response from auth provider.") from exc
            token = data.get("access_token")
            if not token:
                logger.error("Access token missing in My Account token exchange response.")
                raise HTTPException(status_code=502, detail="Invalid response from auth provider.")
            return token

    return await _with_retry(_exchange)

# ── 10. TOKEN VAULT ───────────────────────────────────────────────────────
async def exchange_for_github_token(refresh_token: str) -> str:
    async def _exchange():
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"https://{AUTH0_DOMAIN}/oauth/token",
                json={
                    "grant_type":           "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
                    "client_id":            AUTH0_CLIENT_ID,
                    "client_secret":        AUTH0_CLIENT_SECRET,
                    "subject_token":        refresh_token,
                    "subject_token_type":   "urn:ietf:params:oauth:token-type:refresh_token",
                    "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
                    "connection":           "github",
                },
            )
            try:
                data = response.json()
            except ValueError as exc:
                raise HTTPException(status_code=502, detail="Invalid response from auth provider.") from exc

            github_token = data.get("access_token")
            if not github_token:
                error       = data.get("error", "unknown")
                description = data.get("error_description", "")
                logger.error(f"Token Vault exchange failed: {error} — {description}")
                raise ConsentRequiredError(connection="github", authorization_url=AUTH0_URL)

            logger.info("Token Vault: GitHub token retrieved successfully")
            return github_token

    return await _with_retry(_exchange)

# ── 11. PII REDACTION ─────────────────────────────────────────────────────
def redact_pii(text: str) -> str:
    text = re.sub(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)
    text = re.sub(r'(?i)(secret.{0,20}["\s:=]+)[A-Za-z0-9/+=]{40}', r'\1[REDACTED_SECRET]', text)
    text = re.sub(r'\bAKIA[0-9A-Z]{16}\b', '[REDACTED_AWS_KEY_ID]', text)
    text = re.sub(
        r'(?i)(password|passwd|token|api_key|apikey|secret_key)\s*[:=]\s*[^\s,\n"\']{8,}',
        r'\1=[REDACTED]', text,
    )
    return text

# ── 12. TOOL 1: FETCH IAC FILES ───────────────────────────────────────────
async def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
    try:
        config        = ensure_config()
        refresh_token = config.get("configurable", {}).get("_credentials", {}).get("refresh_token")
        job_id        = config.get("configurable", {}).get("_job_id", "Internal")

        if not refresh_token:
            raise ConsentRequiredError(connection="github", authorization_url=AUTH0_URL)

        github_token = await exchange_for_github_token(refresh_token)

        def _collect_files() -> list[str]:
            g    = Github(github_token)
            repo = g.get_repo(f"{repo_owner}/{repo_name}")

            iac_files    = []
            visited_dirs = 0
            MAX_DIRS     = 200

            raw_contents = repo.get_contents("")
            contents     = raw_contents if isinstance(raw_contents, list) else [raw_contents]

            while contents and len(iac_files) < MAX_IAC_FILES:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    if visited_dirs >= MAX_DIRS:
                        break
                    visited_dirs += 1
                    dir_contents  = repo.get_contents(file_content.path)
                    contents.extend(dir_contents if isinstance(dir_contents, list) else [dir_contents])
                elif file_content.name.endswith((".tf", ".yaml", ".yml", ".json")):
                    try:
                        raw = file_content.decoded_content
                        if raw is None or len(raw) > 1_000_000:
                            continue
                        decoded = raw.decode("utf-8")
                        if decoded.strip():
                            iac_files.append(f"--- Path: {file_content.path} ---\n{decoded}")
                    except Exception as e:
                        logger.warning(f"Failed to decode {file_content.path}: {e}")
            return iac_files

        iac_files = await asyncio.to_thread(_collect_files)

        if not iac_files:
            log_audit_event("FETCH_IAC", "No IaC files found", job_id)
            return "__NO_IAC_FILES__"

        log_audit_event("FETCH_IAC", f"Retrieved {len(iac_files)} files", job_id)
        return redact_pii("\n\n".join(iac_files))

    except ConsentRequiredError:
        raise
    except GithubException as e:
        if e.status == 401:
            raise ConsentRequiredError(connection="github", authorization_url=AUTH0_URL) from e
        raise

fetch_iac_tool = StructuredTool.from_function(
    coroutine=fetch_iac_files,
    name="fetch_iac_files",
    description="Fetch all Terraform/CloudFormation files recursively from a GitHub repository.",
    args_schema=FetchIacFilesArgs,
    handle_tool_errors=False,
)

# ── 13. TOOL 2: SCAN IAC ──────────────────────────────────────────────────
_deepseek_llm = ChatOpenAI(
    model="deepseek-chat",
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
    temperature=0,
)

async def scan_iac_security_issues(code: str) -> str:
    """
    Analyzes IaC code with Checkov + DeepSeek.
    Returns a plain-text block:
      - Finding lines:  [High] resource — description
                        - Why it's risky: ...
                        - Fix: ...
      - Fix blocks:     ### Fixed: <path>
                        ```hcl
                        ...
                        ```
    No other markdown, headings, or prose.
    """
    config = ensure_config()
    job_id = config.get("configurable", {}).get("_job_id", "Internal")

    if code.strip() == "__NO_IAC_FILES__":
        return (
            "No Terraform or CloudFormation files were found in this repository. "
            "Please confirm the repository contains .tf, .yaml, .yml, or .json IaC files."
        )
    if not code.strip():
        return "No IaC files found in the repository. Skipping scan."

    checkov_results = ""
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            parts = re.split(r'---\s*Path:\s*(.+?)\s*---', code)
            if len(parts) > 1:
                for i in range(1, len(parts), 2):
                    rel_path   = parts[i].strip()
                    content    = parts[i + 1].strip()
                    normalized = os.path.normpath(rel_path).lstrip("/\\")
                    target     = pathlib.Path(tmp_dir) / normalized
                    if not target.resolve().is_relative_to(pathlib.Path(tmp_dir).resolve()):
                        logger.warning(f"Blocked path escape: {rel_path}")
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")
            else:
                (pathlib.Path(tmp_dir) / "main.tf").write_text(code, encoding="utf-8")

            checkov_bin = shutil.which("checkov")
            if not checkov_bin:
                logger.warning("checkov not found in PATH — falling back to LLM-only analysis")
                checkov_results = "Checkov not available; LLM-only analysis follows."
            else:
                result = None
                try:
                    result = await asyncio.to_thread(
                        subprocess.run,
                        [checkov_bin, "--directory", tmp_dir, "--output", "json", "--quiet",
                         "--skip-check", "CKV_GIT_1"],
                        capture_output=True, text=True, timeout=90, check=False,
                    )
                except (subprocess.SubprocessError, OSError) as e:
                    checkov_results = f"Checkov execution failed: {e}"

                if result and result.stdout:
                    try:
                        data   = json.loads(result.stdout)
                        failed = data.get("results", {}).get("failed_checks", [])
                        if failed:
                            raw_checkov = "\n".join(
                                f"[{c['check_id']}] {c['check_type']} - {c['resource']} - {c['check_result']['result']}"
                                for c in failed[:10]
                            )
                            checkov_results = redact_pii(raw_checkov)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Checkov output was not valid JSON: {e}")
                        checkov_results = f"Checkov parse error: {result.stdout[:200]}"

    except Exception as e:
        checkov_results = f"Checkov unavailable: {e}"

    file_paths = re.findall(r'---\s*Path:\s*(.+?)\s*---', code)
    paths_list = "\n".join(f"- {p}" for p in file_paths) or "- (unknown)"

    if len(code.encode()) > MAX_LLM_CONTENT_BYTES:
        boundary_re = re.compile(r'---\s*Path:\s*.+?\s*---')
        boundaries  = [m.start() for m in boundary_re.finditer(code)]
        cutoff = 0
        for b in boundaries:
            if len(code[:b].encode()) <= MAX_LLM_CONTENT_BYTES:
                cutoff = b
            else:
                break
        if cutoff:
            code = code[:cutoff] + "\n\n[CONTENT TRUNCATED — remaining files omitted for size]"
        else:
            code = code.encode()[:MAX_LLM_CONTENT_BYTES].decode(errors="replace")
            code += "\n\n[CONTENT TRUNCATED — file too large for full analysis]"

    # ── DEEPSEEK PROMPT ───────────────────────────────────────────────────
    # Output is parsed by the frontend directly — strict format required.
    prompt = f"""You are a senior Cloud Security Engineer reviewing Infrastructure as Code.

Checkov scan results:
{checkov_results or "No Checkov results available."}

Full IaC code for context:
{code}

## YOUR OUTPUT FORMAT — FOLLOW EXACTLY, NO DEVIATION

Output two sections in this exact order. Do NOT add any other text, headings, prose, or explanations outside of what is specified below.

SECTION 1 — FINDINGS (plain text, no markdown except as shown):

List every security issue. For EACH issue use this format on consecutive lines:

[High] resource_name — one-line description of the problem
- Why it's risky: one sentence
- Fix: one sentence

[Medium] resource_name — one-line description
- Why it's risky: one sentence
- Fix: one sentence

STRICT RULES:
- Severity tag MUST be [High], [Medium], or [Low] — first thing on the line, nothing before it.
- NO bold (**), NO italic, NO extra markdown on finding lines or sub-bullets.
- Separator MUST be " — " (space, em dash, space).
- Sub-bullets MUST start with exactly "- Why it's risky:" or "- Fix:" (no bold, no variation).
- For findings with no specific resource: [Medium] (no specific resource) — description
- Do NOT write "Part 1", "Part 2", "Findings:", "Fixed code:", or any section label.
- Do NOT write any sentence before the first [High/Medium/Low] line.

SECTION 2 — FIXED CODE (only if HIGH severity issues exist):

For each file that has HIGH severity issues, output:

### Fixed: exact/path/from/list/above
```hcl
complete corrected file here
```

STRICT RULES:
- "### Fixed:" must be on its own line, followed immediately by the file path.
- Use EXACTLY the filename from the list: {paths_list}
- Do NOT rename files.
- Include the COMPLETE file content — not just changed lines.
- Minimum changes: HIGH severity only. Preserve all resource/variable names.
- Replace 0.0.0.0/0 ingress with 10.0.0.0/8.
- Replace public-read ACL with private.
- Set all block_public_* to true.
- Replace wildcard Action/Resource "*" with least-privilege equivalents.
- Do NOT add new resources.
- If no HIGH severity issues exist, output nothing for Section 2."""

    response  = await _deepseek_llm.ainvoke(prompt)
    corrected = response.content
    corrected = redact_pii(corrected)

    # Normalize "### Fixed:" paths back to exact source paths
    llm_fixed_paths = re.findall(r'### Fixed:\s*([^\n]+)', corrected)
    if len(llm_fixed_paths) == len(file_paths):
        for llm_path, real_path in zip(llm_fixed_paths, file_paths):
            corrected = corrected.replace(f"### Fixed: {llm_path}", f"### Fixed: {real_path}", 1)
    else:
        for real_path in file_paths:
            fname = pathlib.Path(real_path).name
            corrected = re.sub(
                r'### Fixed:\s*[^\n]*' + re.escape(fname),
                f"### Fixed: {real_path}",
                corrected,
            )

    log_audit_event("AI_SCAN", "Hybrid Checkov + LLM analysis completed", job_id)
    return corrected

scan_tool = StructuredTool.from_function(
    coroutine=scan_iac_security_issues,
    name="scan_iac_security_issues",
    description="Analyze IaC code for security issues using rule-based scanning + LLM explanation.",
    args_schema=ScanIacArgs,
)

# ── 14. TOOL 3: PREVIEW FIX DIFF ─────────────────────────────────────────
async def _create_fix_pr(
    repo_owner: str, repo_name: str, branch: str, title: str, body: str,
    files_to_change: List[FileChange], dry_run: bool = True,
) -> str:
    config = ensure_config()
    job_id = config.get("configurable", {}).get("_job_id", "Internal")

    if dry_run:
        # Return ONLY the fix blocks — no PR metadata, no prose.
        # The frontend reads these directly; any extra text causes rendering noise.
        lines = []
        for f in files_to_change:
            ext  = f.path.rsplit(".", 1)[-1] if "." in f.path else ""
            lang = {"tf": "hcl", "yaml": "yaml", "yml": "yaml", "json": "json"}.get(ext, "")
            lines.append(f"### Fixed: {f.path}")
            lines.append(f"```{lang}\n{f.content}\n```")
        log_audit_event("DRY_RUN_PR", f"Suggested fix for {repo_owner}/{repo_name}", job_id)
        return "\n".join(lines)

    # Live PR creation (dry_run=False path — not currently reachable)
    repo        = None
    ref_created = False
    try:
        refresh_token = config.get("configurable", {}).get("_credentials", {}).get("refresh_token")
        github_token  = await exchange_for_github_token(refresh_token)

        def _push_changes():
            nonlocal repo, ref_created
            g    = Github(github_token)
            repo = g.get_repo(f"{repo_owner}/{repo_name}")
            base_sha = repo.get_branch(repo.default_branch).commit.sha
            repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
            ref_created = True
            for fc in files_to_change:
                try:
                    existing = repo.get_contents(fc.path, ref=branch)
                    repo.update_file(path=fc.path, message=f"Security fix: {title}",
                                     content=fc.content, sha=existing.sha, branch=branch)
                except GithubException as e:
                    if e.status == 404:
                        repo.create_file(path=fc.path, message=f"Security fix: {title}",
                                         content=fc.content, branch=branch)
                    else:
                        raise
            pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
            return pr.html_url

        pr_url = await asyncio.to_thread(_push_changes)
        log_audit_event("CREATE_PR", f"PR created for {repo_owner}/{repo_name}", job_id)
        return f"Success! PR created: {pr_url}"

    except ConsentRequiredError:
        raise
    except Exception as e:
        if ref_created and repo is not None:
            try:
                def _cleanup():
                    repo.get_git_ref(f"heads/{branch}").delete()
                await asyncio.to_thread(_cleanup)
            except Exception as ce:
                logger.warning(f"Failed to cleanup branch {branch}: {ce}")
        return f"PR creation failed (rolled back branch): {e}"

async def propose_fix_pr(
    repo_owner: str, repo_name: str, branch: str, title: str, body: str,
    files_to_change: List[FileChange],
) -> str:
    """Always dry-run."""
    return await _create_fix_pr(
        repo_owner=repo_owner, repo_name=repo_name, branch=branch,
        title=title, body=body, files_to_change=files_to_change, dry_run=True,
    )

propose_fix_tool = StructuredTool.from_function(
    coroutine=propose_fix_pr,
    name="preview_fix_diff",
    description=(
        "Generate a diff preview for HIGH severity security fixes. "
        "Does NOT create a real PR. Call only when HIGH severity issues were found."
    ),
    args_schema=ProposeFixArgs,
    handle_tool_errors=False,
)

# ── 15. AGENT ─────────────────────────────────────────────────────────────
tools = [fetch_iac_tool, scan_tool, propose_fix_tool]

agent_llm = ChatOpenAI(
    model="grok-3-mini",
    api_key=os.environ.get("XAI_API_KEY"),
    base_url="https://api.x.ai/v1",
    temperature=0,
    model_kwargs={"tool_choice": "auto"},
)

# ── GROK SYSTEM PROMPT ────────────────────────────────────────────────────
# Grok's ONLY job is to orchestrate tools and write ONE plain summary sentence.
# The findings and fix blocks come from DeepSeek via the tool outputs — Grok
# must not copy, reformat, or augment them.
system_prompt = """You are IaC Sentinel, an Infrastructure-as-Code security scanner.

REQUIRED WORKFLOW — execute every step in order, no skipping:

STEP 1: Call fetch_iac_files with the repo_owner and repo_name from the message.

STEP 2: Call scan_iac_security_issues with the EXACT raw string returned by step 1.

STEP 3: If the scan output contains any [High] severity lines AND contains "### Fixed:" sections,
        call preview_fix_diff. Extract each "### Fixed: <path>" block from the scan output and
        pass the file path and complete code content as files_to_change entries.
        Skip this step if there are no [High] findings.

STEP 4: Write your final response as ONE SINGLE SENTENCE only.
        The sentence must state: the repository name, the total number of findings,
        how many are High / Medium / Low, and the main vulnerability types found.
        End with a period. Nothing else — no headings, no lists, no findings, no code.

ABSOLUTE RULES:
- Do NOT copy findings from the scan output into your response.
- Do NOT copy fixed code into your response.
- Do NOT write headings, bullet points, or any markdown.
- Do NOT add any text beyond the single summary sentence."""

agent_executor = create_react_agent(agent_llm, tools, prompt=system_prompt)

# ── 16. REQUEST MODELS ────────────────────────────────────────────────────
class ActRequest(BaseModel):
    repo_owner:   str
    repo_name:    str
    user_message: str = "Scan this repository for IaC security issues and propose fixes."

    @field_validator("repo_owner", "repo_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9._-]{1,100}$', v):
            raise ValueError("Invalid name — alphanumeric, hyphens, dots, underscores only")
        return v

    @field_validator("user_message")
    @classmethod
    def validate_user_message(cls, v: str) -> str:
        if len(v.encode()) > MAX_USER_MESSAGE_BYTES:
            raise ValueError(f"user_message exceeds maximum length of {MAX_USER_MESSAGE_BYTES} bytes")
        return v

class ConnectRequest(BaseModel):
    redirect_uri: str = REDIRECT_URI

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect_uri(cls, v: str) -> str:
        if v not in ALLOWED_REDIRECT_URIS:
            raise ValueError(f"redirect_uri not allowed: {v}")
        return v

class CompleteRequest(BaseModel):
    auth_session:  str
    connect_code:  str
    redirect_uri:  str = REDIRECT_URI

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect_uri(cls, v: str) -> str:
        if v not in ALLOWED_REDIRECT_URIS:
            raise ValueError(f"redirect_uri not allowed: {v}")
        return v

class TokenRequest(BaseModel):
    code:         str
    redirect_uri: str = REDIRECT_URI

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect_uri(cls, v: str) -> str:
        if v not in ALLOWED_REDIRECT_URIS:
            raise ValueError(f"redirect_uri not allowed: {v}")
        return v

# ── 17. AGENT RUNNER ──────────────────────────────────────────────────────
def _parse_scan_output(raw: str) -> dict:
    """
    Parses DeepSeek's structured output into separate fields so the frontend
    never has to do string surgery on a concatenated blob.

    Returns:
        {
          "findings_text": str,   # just the [High/Medium/Low] blocks
          "fix_blocks":    str,   # just the ### Fixed: ... ``` blocks
        }
    """
    if not raw or not raw.strip():
        return {"findings_text": "", "fix_blocks": ""}

    # Split at the first "### Fixed:" line
    split = re.split(r'(?m)^(### Fixed:)', raw, maxsplit=1)
    if len(split) == 3:
        findings_text = split[0].strip()
        fix_blocks    = (split[1] + split[2]).strip()
    else:
        findings_text = raw.strip()
        fix_blocks    = ""

    return {"findings_text": findings_text, "fix_blocks": fix_blocks}


async def run_agent(job_id: str, req: ActRequest, refresh_token: SensitiveStr):
    """
    Executes the agent and stores a STRUCTURED result payload.

    Job payload on success:
        {
          "status":        "done",
          "summary":       str,   # Grok's one-sentence summary
          "findings_text": str,   # DeepSeek finding blocks only
          "fix_blocks":    str,   # DeepSeek ### Fixed: blocks only
          "recent_audit":  list,
        }
    """
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. Request: {req.user_message}"
        result      = await agent_executor.ainvoke(
            {"messages": [HumanMessage(content=context_msg)]},
            config={"configurable": {
                "_credentials": {"refresh_token": refresh_token.reveal()},
                "_job_id":      job_id,
            }},
        )

        # Grok's final message = the one-sentence summary
        summary = result["messages"][-1].content.strip()

        # Find DeepSeek's raw scan output from the tool message history.
        # We prefer the scan_iac_security_issues tool result over preview_fix_diff
        # because the scan output has BOTH findings AND fix blocks, while
        # preview_fix_diff only has fix blocks (and previously caused duplication).
        scan_raw = ""
        for msg in result["messages"]:
            msg_name = getattr(msg, "name", None)
            msg_type = getattr(msg, "type", None)
            content  = str(getattr(msg, "content", ""))

            if msg_name == "scan_iac_security_issues" or (
                msg_type == "tool" and (
                    "[High]" in content or "[Medium]" in content or "[Low]" in content
                )
            ):
                scan_raw = content
                break

        parsed = _parse_scan_output(scan_raw)

        await update_job(job_id, {
            "status":        "done",
            "summary":       summary,
            "findings_text": parsed["findings_text"],
            "fix_blocks":    parsed["fix_blocks"],
            "recent_audit":  list(AUDIT_LOG)[-5:],
        })

    except ConsentRequiredError as e:
        log_audit_event("CONSENT_REQUIRED", f"Consent required: {e.connection}", job_id)
        await update_job(job_id, {
            "status":            "error",
            "error":             "consent_required",
            "connection":        e.connection,
            "authorization_url": e.authorization_url,
            "instructions": (
                f"Your session has expired or GitHub needs to be reconnected. "
                f"Re-authorise here: {e.authorization_url}"
            ),
        })
    except GithubException as e:
        status = getattr(e, "status", None)
        if status == 404:
            msg = "Repository not found. Check the owner and name, and ensure it is accessible."
        elif status == 403:
            msg = "GitHub access denied. Your token may lack the required 'repo' scope."
        elif status == 429:
            msg = "GitHub rate limit exceeded. Please wait a moment and try again."
        else:
            msg = f"GitHub API error (HTTP {status}): {e.data.get('message', str(e))}"
        logger.error(f"GithubException in job {job_id}: {e}", exc_info=True)
        await update_job(job_id, {"status": "error", "error": msg})
    except Exception as e:
        logger.error(f"Agent error in job {job_id}: {e}", exc_info=True)
        await update_job(job_id, {
            "status": "error",
            "error":  "An internal server error occurred during the scan.",
        })

# ── 18. ENDPOINTS ─────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def read_root():
    html_path = pathlib.Path(__file__).parent / "index.html"
    if html_path.exists():
        return html_path.read_text()
    return "<h1>IaC Sentinel</h1><p>index.html not found.</p>"

@app.get("/auth/login")
async def auth_login(request: Request):
    await purge_expired_sessions()
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    url = (
        f"https://{AUTH0_DOMAIN}/authorize"
        f"?client_id={AUTH0_CLIENT_ID}"
        f"&response_type=code"
        f"&prompt=login"
        f"&scope=openid%20profile%20offline_access"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&audience=https://{AUTH0_DOMAIN}/me/"
    )
    return {"login_url": url}

@app.get("/callback")
async def callback(
    request: Request,
    code: str = None, connect_code: str = None,
    state: str = None, error: str = None,
):
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")

    if connect_code:
        return {"connect_code": connect_code,
                "instructions": "POST to /connect/complete with auth_session and connect_code"}

    saved_state = request.session.get("oauth_state")
    if not state or state != saved_state:
        raise HTTPException(status_code=400, detail="Invalid or missing CSRF state parameter.")

    if code:
        return {"code": code, "instructions": "POST this code to /auth/token"}

    return {"message": "Callback received but no code found"}

@app.post("/auth/token")
async def auth_token(req: TokenRequest, request: Request):
    await purge_expired_sessions()
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type":    "authorization_code",
                "code":          req.code,
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "redirect_uri":  req.redirect_uri,
            },
        )
        try:
            data = response.json()
        except ValueError:
            raise HTTPException(status_code=502, detail="Invalid response from auth provider.")

        refresh_token = data.get("refresh_token")
        if refresh_token:
            session_id = await create_session(refresh_token)
            request.session["session_id"] = session_id
            log_audit_event("USER_LOGIN", "User established secure session")
            return {"message": "Logged in successfully."}

        logger.error(f"No refresh token. Auth0 error: {data.get('error')} — {data.get('error_description')}")
        raise HTTPException(status_code=400, detail="Could not obtain refresh token")

@app.post("/auth/logout")
async def auth_logout(request: Request):
    session_id = request.session.get("session_id")
    if session_id:
        await delete_session(session_id)
    request.session.clear()
    log_audit_event("USER_LOGOUT", "User session cleared")
    return {"message": "Logged out successfully."}

@app.post("/connect/github")
async def connect_github(req: ConnectRequest, request: Request, user=Depends(get_current_user)):
    my_account_token = await get_my_account_token(request)
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/connect",
            headers={"Authorization": f"Bearer {my_account_token}", "Content-Type": "application/json"},
            json={
                "connection":    "github",
                "redirect_uri":  req.redirect_uri,
                "state":         secrets.token_urlsafe(32),
                "scopes":        ["repo", "read:user", "offline_access"],
            },
        )
        if response.status_code not in (200, 201):
            raise HTTPException(status_code=response.status_code, detail="Failed to initiate connection.")
        data         = response.json()
        ticket       = data.get("connect_params", {}).get("ticket")
        connect_uri  = data.get("connect_uri")
        auth_session = data.get("auth_session")
        return {"auth_session": auth_session, "connect_url": f"{connect_uri}?ticket={ticket}"}

@app.post("/connect/complete")
async def connect_complete(req: CompleteRequest, request: Request, user=Depends(get_current_user)):
    my_account_token = await get_my_account_token(request)
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/complete",
            headers={"Authorization": f"Bearer {my_account_token}", "Content-Type": "application/json"},
            json={"auth_session": req.auth_session, "connect_code": req.connect_code,
                  "redirect_uri": req.redirect_uri},
        )
        if response.status_code not in (200, 201):
            raise HTTPException(status_code=response.status_code, detail="Failed to complete connection.")
        log_audit_event("GITHUB_CONNECTED", "GitHub account connected to Token Vault")
        return {"message": "GitHub account successfully connected to Token Vault!"}

@app.get("/connect/status")
async def connect_status(request: Request, user=Depends(get_current_user)):
    my_account_token = await get_my_account_token(request)
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/accounts",
            headers={"Authorization": f"Bearer {my_account_token}"},
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch connected accounts.")
        try:
            return response.json()
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="Invalid response from auth provider.") from exc

@app.post("/act")
@limiter.limit("5/minute")
async def act_endpoint(
    req: ActRequest, request: Request,
    background_tasks: BackgroundTasks, user=Depends(get_current_user),
):
    if not await _increment_jobs():
        raise HTTPException(
            status_code=429,
            detail=f"Too many concurrent scans (max {MAX_CONCURRENT_JOBS}). Please wait.",
        )

    try:
        session_id = request.session.get("session_id")
        if not session_id:
            raise HTTPException(status_code=401, detail="Session expired. Please re-authenticate.")

        job_id = make_job_id(session_id)
        await store_job(job_id, {
            "status":     "running",
            "session_id": session_id,
            "repo":       f"{req.repo_owner}/{req.repo_name}",
        })

        refresh_token = SensitiveStr(user.get("refresh_token", ""))

        async def _guarded_run():
            try:
                await run_agent(job_id, req, refresh_token)
            finally:
                await _decrement_jobs()

        background_tasks.add_task(_guarded_run)
    except HTTPException:
        await _decrement_jobs()
        raise
    except Exception:
        await _decrement_jobs()
        raise

    return {"job_id": job_id, "poll_url": f"/result/{job_id}", "stream_url": f"/stream/{job_id}"}

@app.get("/result/{job_id}")
async def get_result(job_id: str, request: Request, user=Depends(get_current_user)):
    job = await get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    current_session = request.session.get("session_id")
    job_session     = job.get("session_id")
    if not (current_session and job_session and current_session == job_session):
        raise HTTPException(status_code=403, detail="Forbidden")
    return job

@app.get("/stream/{job_id}")
async def stream_result(job_id: str, request: Request, user=Depends(get_current_user)):
    async def event_generator():
        current_session = request.session.get("session_id")
        deadline = time.monotonic() + STREAM_TIMEOUT_SECONDS
        while True:
            if time.monotonic() > deadline:
                yield 'data: {"error":"stream timeout — poll /result for final status"}\n\n'
                break
            job = await get_job(job_id)
            if not job:
                yield 'data: {"error":"not found"}\n\n'
                break
            job_session = job.get("session_id")
            if not (current_session and job_session and current_session == job_session):
                yield 'data: {"error":"forbidden"}\n\n'
                break
            yield f"data: {json.dumps(job)}\n\n"
            if job["status"] in ("done", "error"):
                break
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/health")
def health():
    return {
        "status":      "healthy",
        "token_vault": "active" if _AUTH0_SDK_AVAILABLE else "mock-mode",
        "job_store":   "redis" if redis_client else "memory",
    }

@app.get("/audit")
async def get_audit(request: Request, user=Depends(get_current_user)):
    session_id   = request.session.get("session_id")
    auth_actions = {"USER_LOGIN", "USER_LOGOUT", "GITHUB_CONNECTED", "CONSENT_REQUIRED"}
    user_logs = [
        e for e in AUDIT_LOG
        if e.get("action") in auth_actions
        or verify_job_id(e.get("target", ""), session_id)
    ]
    return {"total_events": len(user_logs), "logs": list(reversed(user_logs))}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("application:app", host="127.0.0.1", port=8000, reload=True)