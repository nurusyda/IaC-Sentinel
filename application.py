import asyncio
import os
import shutil
import logging
import sys
import subprocess
import json
import uuid
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
AUDIT_LOG: deque = deque(maxlen=50)

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
MAX_LLM_CONTENT_BYTES  = 400_000   # cap content sent to DeepSeek

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

# ── 7. APP INIT ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# Lock for session store mutations (protects OrderedDict from concurrent async access)
_sessions_lock = asyncio.Lock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IaC Sentinel starting up with Auth0 Token Vault...")
    # Background task: periodically purge expired sessions to avoid unbounded growth
    purge_task = asyncio.create_task(_periodic_session_purge())
    yield
    purge_task.cancel()
    try:
        await purge_task
    except asyncio.CancelledError:
        pass
    logger.info("IaC Sentinel shutting down.")

async def _periodic_session_purge():
    """Purge expired sessions every 10 minutes rather than only on login."""
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
        # NOTE: unsafe-inline is required because all JS lives in index.html.
        # To harden further, move JS to a static file and use a nonce or hash.
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

# Serve static assets (app.js, app.css)
_static_dir = pathlib.Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
else:
    logger.warning("static/ directory not found — /static/* routes will 404")

# application alias for Elastic Beanstalk: EB expects a callable named "application"
application = app

# ── 7.5 JOB STORE (Redis / in-memory fallback) ───────────────────────────
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
# Job IDs are bound to the session that created them using a 16-hex-char
# truncated HMAC-SHA256 (64 bits). This prevents one authenticated user from
# polling another user's job by guessing or enumerating job IDs.
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
    """Returns True if slot acquired, False if at capacity."""
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
    """Internal sync helper — must be called with _sessions_lock held."""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {"refresh_token": refresh_token, "created_at": time.time()}
    while len(sessions) > MAX_STORED_SESSIONS:
        evicted_id, _ = sessions.popitem(last=False)
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
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing. Please re-authenticate.")

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type":    "refresh_token",
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "refresh_token": refresh_token,
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

# ── 10. TOKEN VAULT ───────────────────────────────────────────────────────
async def exchange_for_github_token(refresh_token: str) -> str:
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

# ── 11. PII REDACTION ─────────────────────────────────────────────────────
def redact_pii(text: str) -> str:
    # Phone numbers
    text = re.sub(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)
    # SSN
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
    # Email
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)
    # AWS secret key values (40-char base64-ish)
    text = re.sub(r'(?i)(secret.{0,20}["\s:=]+)[A-Za-z0-9/+=]{40}', r'\1[REDACTED_SECRET]', text)
    # AWS access key IDs
    text = re.sub(r'\bAKIA[0-9A-Z]{16}\b', '[REDACTED_AWS_KEY_ID]', text)
    # Generic key=value credential patterns
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
                    # Path traversal guard: resolve() works correctly on non-existent
                    # paths in Python 3.6+ (does not raise, just normalises).
                    # Requires Python >= 3.9 for Path.is_relative_to().
                    if not target.resolve().is_relative_to(pathlib.Path(tmp_dir).resolve()):
                        logger.warning(f"Blocked path escape: {rel_path}")
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")
            else:
                (pathlib.Path(tmp_dir) / "main.tf").write_text(code, encoding="utf-8")

            checkov_bin = shutil.which("checkov")
            if not checkov_bin:
                # Checkov is optional: fall back to LLM-only analysis and log clearly.
                # This allows the app to run in environments without Checkov installed,
                # but operators should ensure Checkov is present in production.
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

    # Truncate at the last complete file boundary before the byte limit so we
    # never split a "--- Path: ..." header mid-way, which would corrupt path
    # matching downstream.
    if len(code.encode()) > MAX_LLM_CONTENT_BYTES:
        # Find all file-boundary offsets and keep the largest set that fits
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
            # Single file larger than the limit — hard truncate with a warning
            code = code.encode()[:MAX_LLM_CONTENT_BYTES].decode(errors="replace")
            code += "\n\n[CONTENT TRUNCATED — file too large for full analysis]"

    prompt = f"""You are a senior Cloud Security Engineer reviewing Infrastructure as Code.

Checkov scan results:
{checkov_results or "No Checkov results available."}

Full IaC code for context:
{code}

## Your task

### Part 1 — Security findings
List every security issue found. For each one use exactly this format:

[Severity: High/Medium/Low] **Resource: <resource_name>** — <one-line description>
- **Why it's risky:** <explanation>
- **Fix:** <what needs to change>

Cover: wildcard IAM permissions, public S3 buckets, missing CloudTrail, security groups open to 0.0.0.0/0, missing encryption at rest, hardcoded secrets.

### Part 2 — Fixed code
The files in this repository are:
{paths_list}

For every file with HIGH severity issues, output the COMPLETE fixed file.
Use EXACTLY the filename from the list above — do not rename it.

### Fixed: <file_path>
```hcl
<complete corrected file content here>
```

Rules: minimum changes for HIGH severity only; preserve all resource/variable names; replace 0.0.0.0/0 ingress with 10.0.0.0/8; replace public-read ACL with private; set all block_public_* to true; replace wildcard Action/Resource "*" with least-privilege equivalents. Do NOT add new resources."""

    response  = await _deepseek_llm.ainvoke(prompt)
    corrected = response.content

    # Apply PII redaction to LLM output — the model may echo back secrets
    # that were present in the source code even after our input-side redaction.
    corrected = redact_pii(corrected)

    # Fix LLM-reported paths back to canonical repo paths (by position match)
    llm_fixed_paths = re.findall(r'### Fixed:\s*([^\n]+)', corrected)
    if len(llm_fixed_paths) == len(file_paths):
        for llm_path, real_path in zip(llm_fixed_paths, file_paths):
            corrected = corrected.replace(f"### Fixed: {llm_path}", f"### Fixed: {real_path}", 1)
    else:
        # Fall back: best-substring match
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

# ── 14. TOOL 3: PREVIEW FIX DIFF ──────────────────────────────────────────
async def _create_fix_pr(
    repo_owner: str, repo_name: str, branch: str, title: str, body: str,
    files_to_change: List[FileChange], dry_run: bool = True,
) -> str:
    config = ensure_config()
    job_id = config.get("configurable", {}).get("_job_id", "Internal")

    if dry_run:
        lines = [f"## Proposed fixes for `{repo_owner}/{repo_name}`\n",
                 f"**PR title:** {title}\n",
                 f"**Branch:** `{branch}`\n"]
        if body:
            lines.append(f"{body}\n")
        for f in files_to_change:
            ext  = f.path.rsplit(".", 1)[-1] if "." in f.path else ""
            lang = {"tf": "hcl", "yaml": "yaml", "yml": "yaml", "json": "json"}.get(ext, "")
            lines.append(f"### `{f.path}`")
            lines.append(f"```{lang}\n{f.content}\n```")
        log_audit_event("DRY_RUN_PR", f"Suggested fix for {repo_owner}/{repo_name}", job_id)
        return "\n".join(lines)

    repo        = None
    ref_created = False
    try:
        refresh_token = config.get("configurable", {}).get("_credentials", {}).get("refresh_token")
        github_token  = await exchange_for_github_token(refresh_token)
        g    = Github(github_token)
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        base_sha = repo.get_branch(repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
        ref_created = True

        for f in files_to_change:
            try:
                existing = repo.get_contents(f.path, ref=branch)
                repo.update_file(path=f.path, message=f"Security fix: {title}",
                                 content=f.content, sha=existing.sha, branch=branch)
            except GithubException as e:
                if e.status == 404:
                    repo.create_file(path=f.path, message=f"Security fix: {title}",
                                     content=f.content, branch=branch)
                else:
                    raise

        pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
        log_audit_event("CREATE_PR", f"PR #{pr.number} created", job_id)
        return f"Success! PR created: {pr.html_url}"

    except ConsentRequiredError:
        raise
    except Exception as e:
        if ref_created and repo is not None:
            try:
                repo.get_git_ref(f"heads/{branch}").delete()
            except Exception as ce:
                logger.warning(f"Failed to cleanup branch {branch}: {ce}")
        return f"PR creation failed (rolled back branch): {e}"

async def propose_fix_pr(
    repo_owner: str, repo_name: str, branch: str, title: str, body: str,
    files_to_change: List[FileChange],
) -> str:
    """Always dry-run — the AI cannot override this."""
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

# System prompt is the authoritative source of the agent's tool-call contract.
# Any changes to tool names or workflow steps must be reflected here.
system_prompt = """You are IaC Sentinel, an Infrastructure-as-Code security scanner.

REQUIRED WORKFLOW — follow every step in order:

STEP 1: Call fetch_iac_files with repo_owner and repo_name from the message.

STEP 2: Call scan_iac_security_issues with the EXACT output from step 1.

STEP 3: If the scan output contains any [Severity: High] findings AND includes
        "### Fixed: <path>" sections, call preview_fix_diff.
        - files_to_change: for EACH "### Fixed: <path>" section, include one entry with
          path = the file path and content = the COMPLETE file content verbatim.
        Do NOT call preview_fix_diff if there are no HIGH severity issues.

STEP 4: Write your final response:
        1. Short paragraph summarising what was found.
        2. Full scan findings (severities, resource names, explanations).
        3. If fixes were previewed: note that the fixed code is shown below, and that
           only HIGH severity issues were addressed — Medium/Low require manual review.
        Do NOT respond with text before completing all tool calls."""

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
async def run_agent(job_id: str, req: ActRequest, refresh_token: SensitiveStr):
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. Request: {req.user_message}"
        result      = await agent_executor.ainvoke(
            {"messages": [HumanMessage(content=context_msg)]},
            config={"configurable": {
                "_credentials": {"refresh_token": refresh_token.reveal()},
                "_job_id":      job_id,
            }},
        )
        await update_job(job_id, {
            "status":       "done",
            "response":     result["messages"][-1].content,
            "recent_audit": list(AUDIT_LOG)[-5:],
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
        # Surface GitHub-specific errors with actionable detail rather than
        # collapsing everything into a generic message.
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
        data     = response.json()
        ticket   = data.get("connect_params", {}).get("ticket")
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

    # Wrap everything after _increment_jobs in a try/finally so the counter is
    # always released if setup fails before the background task is registered.
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
    # Allowlist logic: both must be present and equal
    if not (current_session and job_session and current_session == job_session):
        raise HTTPException(status_code=403, detail="Forbidden")
    return job

@app.get("/stream/{job_id}")
async def stream_result(job_id: str, request: Request, user=Depends(get_current_user)):
    async def event_generator():
        current_session = request.session.get("session_id")
        while True:
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
    session_id  = request.session.get("session_id")
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