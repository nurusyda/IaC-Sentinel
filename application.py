import os
import shutil
import logging
import sys
import subprocess
import json
import warnings
import uuid
import secrets
import asyncio
import httpx
from collections import deque, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any, List

# ── 1. INITIALIZE LOGGING ──────────────────────────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── 2. AUTH0 AI SDK ───────────────────────────────────────────────────────
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
    logger.info("🚀 AUTH0 SDK LOADED: Token Vault is active.")

except ImportError as e:
    if not MOCK_AUTH0:
        logger.critical("Auth0 SDK failed to load. Aborting startup because MOCK_AUTH0 is not true.")
        raise RuntimeError("Auth0 SDK not found and MOCK_AUTH0=false. Aborting startup.") from e

    _AUTH0_SDK_AVAILABLE = False
    logger.warning(f"⚠️ Auth0 SDK failed to load (using mock-mode): {e}")

    class ConsentRequiredError(Exception):
        def __init__(self, connection: str, authorization_url: str = None):
            self.connection = connection
            self.authorization_url = authorization_url

    class Auth0AI:
        pass

# Auth0AI is instantiated here to confirm SDK availability at startup.
# The Connected Accounts flow and token exchange use Auth0's /oauth/token
# endpoint directly (see exchange_for_github_token) because the SDK's
# with_token_vault decorator is incompatible with LangGraph's tool execution
# model — it triggers a CIBA interrupt instead of executing the tool.
auth0_ai = Auth0AI()

# ── 3. CORE IMPORTS ───────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from github import Github, GithubException
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage
from langchain_core.runnables import ensure_config
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from dotenv import load_dotenv

load_dotenv()

# ── 4. AUDIT LOG SETUP ────────────────────────────────────────────────────
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

# ── 5. CONFIG ─────────────────────────────────────────────────────────────
MAX_IAC_FILES = 15
MAX_CONCURRENT_JOBS = 10
MAX_STORED_JOBS = 100  # Evict oldest jobs beyond this to prevent memory leak

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", "")

AUTH0_URL = os.environ.get("AUTH0_GITHUB_AUTHORIZE_URL")
if not AUTH0_URL and os.environ.get("ENVIRONMENT") == "production":
    raise RuntimeError("AUTH0_GITHUB_AUTHORIZE_URL is required in production")
AUTH0_URL = AUTH0_URL or f"https://{AUTH0_DOMAIN}/authorize"

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY:
    raise RuntimeError("SESSION_SECRET_KEY environment variable is required")

REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback")

ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_RAW.split(",")]

# ── 6. APP INIT ───────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IaC Sentinel starting up with Auth0 Token Vault...")
    yield
    logger.info("IaC Sentinel shutting down.")

app = FastAPI(
    title="IaC Sentinel",
    description="AI-powered IaC security scanner using Auth0 Token Vault.",
    version="1.0.0",
    lifespan=lifespan,
)

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

application = app  # Required for Elastic Beanstalk

# ── 6.5 BACKGROUND JOBS STORE ─────────────────────────────────────────────
# OrderedDict preserves insertion order so we can evict oldest entries.
# Capped at MAX_STORED_JOBS to prevent unbounded memory growth.
# TODO: Move to Redis for production to survive worker restarts.
jobs: OrderedDict = OrderedDict()

def store_job(job_id: str, data: Dict[str, Any]):
    """Store a job result, evicting the oldest entry if over the cap."""
    jobs[job_id] = data
    while len(jobs) > MAX_STORED_JOBS:
        jobs.popitem(last=False)  # Remove oldest

# ── 7. TOOL SCHEMAS (Pydantic) ────────────────────────────────────────────
class FetchIacFilesArgs(BaseModel):
    repo_owner: str = Field(description="GitHub repository owner")
    repo_name: str = Field(description="GitHub repository name")

class ScanIacArgs(BaseModel):
    code: str = Field(
        description=(
            "The EXACT raw code retrieved from the fetch_iac_files tool. "
            "YOU MUST RUN fetch_iac_files FIRST. "
            "DO NOT guess, hallucinate, or make up code."
        )
    )

class FileChange(BaseModel):
    path: str = Field(description="File path relative to repo root")
    content: str = Field(description="New file content with security fixes applied")

class ProposeFixArgs(BaseModel):
    repo_owner: str
    repo_name: str
    branch: str
    title: str
    body: str
    files_to_change: List[FileChange] = Field(
        description="List of files to change, each with a path and new content"
    )

# ── 8. AUTH DEPENDENCIES ──────────────────────────────────────────────────
def get_current_user(request: Request):
    """Dependency to enforce authentication on secured routes."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated. Please complete the login flow.")
    return user

async def get_my_account_token(request: Request) -> str:
    """Exchange user's session refresh token for My Account API access token."""
    user = get_current_user(request)
    refresh_token = user.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing. Please re-authenticate.")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "refresh_token",
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "audience": f"https://{AUTH0_DOMAIN}/me/",
                "scope": "openid profile offline_access create:me:connected_accounts read:me:connected_accounts delete:me:connected_accounts",
            }
        )
        data = response.json()
        token = data.get("access_token")
        if not token:
            logger.error("Failed to get My Account API token from refresh exchange.")
            raise HTTPException(status_code=500, detail="Token exchange failed. Re-authentication required.")
        return token

# ── 9. TOKEN VAULT: Exchange refresh token for GitHub token ───────────────
async def exchange_for_github_token(refresh_token: str) -> str:
    """
    Exchange the user's Auth0 refresh token for a GitHub access token
    stored in Token Vault. The user's GitHub token was stored during
    the /connect/github Connected Accounts flow.

    This calls the Auth0 /oauth/token endpoint directly using the
    Token Vault federated connection grant type (RFC 8693 Token Exchange).
    The auth0-ai SDK's with_token_vault decorator uses the same underlying
    endpoint but requires a LangChain runnable context that is incompatible
    with LangGraph's create_react_agent tool execution model — it triggers
    a CIBA interrupt instead of executing the tool. We call the endpoint
    directly to preserve full agent tool-calling functionality while still
    using Auth0's Token Vault for secure credential storage and retrieval.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "subject_token": refresh_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
                "connection": "github",
            }
        )
        data = response.json()
        github_token = data.get("access_token")

        if not github_token:
            logger.error(f"Token Vault exchange failed: {data}")
            raise ConsentRequiredError(
                connection="github",
                authorization_url=AUTH0_URL,
            )

        logger.info("✅ Token Vault: GitHub token retrieved successfully")
        return github_token

# ── 10. TOOL 1: FETCH IAC FILES ───────────────────────────────────────────
async def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
    try:
        # ── Token Vault Integration ──────────────────────────────────────
        # The user's refresh token is passed via LangChain runnable config
        # from /act → run_agent → agent_executor.ainvoke. We exchange it
        # for the GitHub access token stored in Token Vault during the
        # /connect/github OAuth consent flow.
        config = ensure_config()
        refresh_token = config.get("configurable", {}).get("_credentials", {}).get("refresh_token")

        if not refresh_token:
            raise ConsentRequiredError(
                connection="github",
                authorization_url=AUTH0_URL,
            )

        github_token = await exchange_for_github_token(refresh_token)
        # ────────────────────────────────────────────────────────────────

        g = Github(github_token)
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        iac_files = []
        raw_contents = repo.get_contents("")
        contents = raw_contents if isinstance(raw_contents, list) else [raw_contents]

        while contents and len(iac_files) < MAX_IAC_FILES:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                dir_contents = repo.get_contents(file_content.path)
                if isinstance(dir_contents, list):
                    contents.extend(dir_contents)
                else:
                    contents.append(dir_contents)
            elif file_content.name.endswith((".tf", ".yaml", ".yml", ".json")):
                try:
                    raw = file_content.decoded_content
                    if raw is None:
                        logger.warning(f"Skipping {file_content.path}: no content")
                        continue
                    decoded = raw.decode("utf-8")
                    if decoded.strip():
                        iac_files.append(f"--- Path: {file_content.path} ---\n{decoded}")
                except Exception as e:
                    logger.warning(f"Failed to decode {file_content.path}, skipping. Error: {e}")

        log_audit_event("FETCH_IAC", f"Retrieved {len(iac_files)} files", f"{repo_owner}/{repo_name}")
        return "\n\n".join(iac_files) if iac_files else ""

    except ConsentRequiredError:
        raise
    except GithubException as e:
        if e.status == 401:
            raise ConsentRequiredError(
                connection="github",
                authorization_url=AUTH0_URL,
            ) from e
        raise

fetch_iac_tool = StructuredTool.from_function(
    coroutine=fetch_iac_files,
    name="fetch_iac_files",
    description="Fetch all Terraform/CloudFormation files recursively from a GitHub repository.",
    args_schema=FetchIacFilesArgs,
    handle_tool_errors=False,
)

# ── 11. TOOL 2: SCAN IAC SECURITY ISSUES ─────────────────────────────────
async def scan_iac_security_issues(code: str) -> str:
    if not code.strip():
        return "No IaC files found in the repository. Skipping scan."

    checkov_results = ""
    try:
        import tempfile
        import re

        with tempfile.TemporaryDirectory() as tmp_dir:
            parts = re.split(r'---\s*Path:\s*(.+?)\s*---', code)
            if len(parts) > 1:
                for i in range(1, len(parts), 2):
                    rel_path = parts[i].strip()
                    content = parts[i + 1].strip()

                    normalized = os.path.normpath(rel_path).lstrip("/\\")
                    target_path = os.path.join(tmp_dir, normalized)

                    if not os.path.realpath(target_path).startswith(os.path.realpath(tmp_dir)):
                        logger.warning(f"Blocked path escape: {rel_path}")
                        continue

                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(content)
            else:
                with open(os.path.join(tmp_dir, "main.tf"), "w", encoding="utf-8") as f:
                    f.write(code)

            checkov_bin = shutil.which("checkov")
            if not checkov_bin:
                raise RuntimeError("checkov executable not found in PATH")

            result = None
            try:
                # asyncio.to_thread prevents Checkov (10-30s) from blocking the event loop
                result = await asyncio.to_thread(
                    subprocess.run,
                    [checkov_bin, "--directory", tmp_dir, "--output", "json", "--quiet"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError) as e:
                checkov_results = f"Checkov execution failed: {e}"

            if result and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    failed = data.get("results", {}).get("failed_checks", [])
                    if failed:
                        checkov_results = "\n".join(
                            f"[{c['check_id']}] {c['check_type']} - {c['resource']} - {c['check_result']['result']}"
                            for c in failed[:10]
                        )
                except json.JSONDecodeError as e:
                    logger.warning(f"Checkov output was not valid JSON: {e}")
                    checkov_results = f"Checkov parse error: {result.stdout[:200]}"

    except Exception as e:
        checkov_results = f"Checkov unavailable: {e}"

    # DeepSeek for security analysis — cost-effective for LLM-based review.
    # Using ainvoke (async) to avoid blocking the event loop during long responses.
    llm = ChatOpenAI(
        model="deepseek-chat",
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
        temperature=0,
    )

    prompt = f"""You are a senior Cloud Security Engineer reviewing Infrastructure as Code.

Checkov scan results:
{checkov_results or "No Checkov results available."}

Full IaC code for context:
{code}

Identify and explain ALL security issues including:
- Wildcard IAM permissions (*)
- Public S3 buckets or open ACLs
- Missing CloudTrail logging
- Security groups open to 0.0.0.0/0
- Missing encryption at rest
- Hardcoded secrets or credentials

For each issue output:
[Severity: High/Medium/Low] Issue - Remediation

Be specific. Reference the actual resource names from the code."""

    response = await llm.ainvoke(prompt)
    log_audit_event("AI_SCAN", "Hybrid Checkov + LLM analysis completed")
    return response.content

scan_tool = StructuredTool.from_function(
    coroutine=scan_iac_security_issues,
    name="scan_iac_security_issues",
    description="Analyze IaC code for security issues using rule-based scanning + LLM explanation.",
    args_schema=ScanIacArgs,
)

# ── 12. TOOL 3: PROPOSE FIX PR ────────────────────────────────────────────
async def _create_fix_pr(
    repo_owner: str,
    repo_name: str,
    branch: str,
    title: str,
    body: str,
    files_to_change: List[FileChange],
    dry_run: bool = True,
) -> str:
    if dry_run:
        suggestion = f"[DRY RUN] Would create PR '{title}' on {repo_owner}/{repo_name}\n\n"
        suggestion += "Proposed changes:\n"
        for f in files_to_change:
            suggestion += f"\n--- {f.path} ---\n{f.content}\n"
        log_audit_event("DRY_RUN_PR", f"Suggested fix for {repo_owner}/{repo_name}")
        return suggestion

    repo = None
    ref_created = False
    try:
        config = ensure_config()
        refresh_token = config.get("configurable", {}).get("_credentials", {}).get("refresh_token")
        github_token = await exchange_for_github_token(refresh_token)

        g = Github(github_token)
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        base_sha = repo.get_branch(repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
        ref_created = True

        for f in files_to_change:
            try:
                existing = repo.get_contents(f.path, ref=branch)
                repo.update_file(
                    path=f.path,
                    message=f"Security fix: {title}",
                    content=f.content,
                    sha=existing.sha,
                    branch=branch,
                )
            except GithubException as e:
                if e.status == 404:
                    repo.create_file(
                        path=f.path,
                        message=f"Security fix: {title}",
                        content=f.content,
                        branch=branch,
                    )
                else:
                    raise

        pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
        log_audit_event("CREATE_PR", f"PR #{pr.number} created", f"{repo_owner}/{repo_name}")
        return f"Success! PR created: {pr.html_url}"

    except ConsentRequiredError:
        raise
    except Exception as e:
        if ref_created and repo is not None:
            try:
                repo.get_git_ref(f"heads/{branch}").delete()
            except Exception as cleanup_err:
                logger.warning(f"Failed to cleanup branch {branch}: {cleanup_err}")
        return f"PR creation failed (rolled back branch): {str(e)}"


async def propose_fix_pr(
    repo_owner: str,
    repo_name: str,
    branch: str,
    title: str,
    body: str,
    files_to_change: List[FileChange],
) -> str:
    """Hardcoded to ALWAYS be a dry run. The AI cannot change this."""
    return await _create_fix_pr(
        repo_owner=repo_owner,
        repo_name=repo_name,
        branch=branch,
        title=title,
        body=body,
        files_to_change=files_to_change,
        dry_run=True,
    )

propose_fix_tool = StructuredTool.from_function(
    coroutine=propose_fix_pr,
    name="propose_fix_pr",
    description="Preview security fixes. Does NOT create a real PR.",
    args_schema=ProposeFixArgs,
    handle_tool_errors=False,
)

# ── 13. AGENT ─────────────────────────────────────────────────────────────
tools = [fetch_iac_tool, scan_tool, propose_fix_tool]

# Grok as agent brain — reliable tool calling, OpenAI-compatible API.
# DeepSeek is used inside scan_iac_security_issues for cost-effective analysis.
agent_llm = ChatOpenAI(
    model="grok-3-mini",
    api_key=os.environ.get("XAI_API_KEY"),
    base_url="https://api.x.ai/v1",
    temperature=0,
    model_kwargs={"tool_choice": "auto"},
)

system_prompt = """You are IaC Sentinel. You MUST use tools. Never respond without using tools first.

REQUIRED WORKFLOW - follow exactly:
STEP 1: Call fetch_iac_files with repo_owner and repo_name from the message.
STEP 2: Call scan_iac_security_issues with the output from step 1.
STEP 3: If HIGH severity issues found, call propose_fix_pr.

DO NOT respond with text until you have called fetch_iac_files. This is mandatory."""

agent_executor = create_react_agent(agent_llm, tools, prompt=system_prompt)

# ── 14. REQUEST MODELS ────────────────────────────────────────────────────
class ActRequest(BaseModel):
    repo_owner: str
    repo_name: str
    user_message: str = "Scan this repository for IaC security issues and propose fixes."

class ConnectRequest(BaseModel):
    redirect_uri: str = REDIRECT_URI

class CompleteRequest(BaseModel):
    auth_session: str
    connect_code: str
    redirect_uri: str = REDIRECT_URI

class TokenRequest(BaseModel):
    code: str
    redirect_uri: str = REDIRECT_URI

# ── 15. AGENT RUNNER ──────────────────────────────────────────────────────
async def run_agent(job_id: str, req: ActRequest, refresh_token: str):
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. Request: {req.user_message}"
        result = await agent_executor.ainvoke(
            {"messages": [HumanMessage(content=context_msg)]},
            config={"configurable": {"_credentials": {"refresh_token": refresh_token}}}
        )
        store_job(job_id, {
            "status": "done",
            "response": result["messages"][-1].content,
            "recent_audit": list(AUDIT_LOG)[-5:],
        })
    except ConsentRequiredError as e:
        log_audit_event("CONSENT_REQUIRED", f"Consent required for connection: {e.connection}")
        store_job(job_id, {
            "status": "error",
            "error": "consent_required",
            "connection": e.connection,
            "authorization_url": e.authorization_url,
            "instructions": f"Open this URL to connect GitHub: {e.authorization_url}",
        })
    except Exception as e:
        logger.error(f"Agent error in job {job_id}: {e}", exc_info=True)
        store_job(job_id, {"status": "error", "error": "An internal server error occurred during the scan."})

# ── 16. ENDPOINTS ─────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <html>
        <head>
            <title>IaC Sentinel Demo</title>
            <style>
                body { font-family: -apple-system, sans-serif; padding: 2rem; max-width: 800px; margin: auto; line-height: 1.6; }
                code { background: #f4f4f4; padding: 2px 5px; border-radius: 4px; }
                .notice { background: #e3f2fd; padding: 1rem; border-left: 4px solid #1976d2; margin-top: 1rem; }
            </style>
        </head>
        <body>
            <h1>IaC Sentinel 🛡️</h1>
            <p>Welcome to the IaC Sentinel Hackathon Demo.</p>
            <h3>Getting Started</h3>
            <ol>
                <li><strong>Login:</strong> Start your secure session via <a href="/auth/login" target="_blank">/auth/login</a>.</li>
                <li><strong>Exchange Token:</strong> POST the code from the callback to <code>/auth/token</code> to establish your session.</li>
                <li><strong>Connect GitHub:</strong> Authorize Token Vault access by POSTing to <code>/connect/github</code> and completing the flow.</li>
                <li><strong>Run Scan:</strong> Trigger an AI scan using <code>POST /act</code>.</li>
            </ol>
            <div class="notice">
                <strong>Hackathon Note:</strong> Background jobs and session state are currently stored in-memory for this demo.
                In a full production environment, this would be backed by Redis.
            </div>
        </body>
    </html>
    """

@app.get("/auth/login")
async def auth_login(request: Request):
    """Initiates login with CSRF protection."""
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
    return {"login_url": url, "instructions": "Open login_url in your browser"}

@app.get("/callback")
async def callback(request: Request, code: str = None, connect_code: str = None, state: str = None, error: str = None):
    """Handles OAuth callbacks with state validation."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")

    # Connected Accounts callback — Auth0 secures via ticket, no CSRF needed
    if connect_code:
        return {
            "connect_code": connect_code,
            "instructions": "POST to /connect/complete with your auth_session and this connect_code"
        }

    # CSRF check only for login flow
    saved_state = request.session.get("oauth_state")
    if not state or state != saved_state:
        raise HTTPException(status_code=400, detail="Invalid or missing CSRF state parameter.")

    if code:
        return {
            "code": code,
            "instructions": "POST this code to /auth/token to establish your session"
        }

    return {"message": "Callback received but no code found"}

@app.post("/auth/token")
async def auth_token(req: TokenRequest, request: Request):
    """Exchanges code for tokens and creates a secure session."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": req.code,
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "redirect_uri": req.redirect_uri,
            }
        )
        data = response.json()
        refresh_token = data.get("refresh_token")

        if refresh_token:
            request.session["user"] = {"refresh_token": refresh_token}
            log_audit_event("USER_LOGIN", "User established secure session")
            return {"message": "Logged in successfully. You can now use /connect/* and /act endpoints."}

        logger.error(f"Failed to obtain refresh token: {data}")
        raise HTTPException(status_code=400, detail="Could not obtain refresh token")

@app.post("/auth/logout")
async def auth_logout(request: Request):
    """Clears the user session."""
    request.session.clear()
    log_audit_event("USER_LOGOUT", "User session cleared")
    return {"message": "Logged out successfully."}

@app.post("/connect/github")
async def connect_github(req: ConnectRequest, request: Request, user=Depends(get_current_user)):
    """Initiates GitHub connection for the authenticated user."""
    my_account_token = await get_my_account_token(request)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/connect",
            headers={
                "Authorization": f"Bearer {my_account_token}",
                "Content-Type": "application/json",
            },
            json={
                "connection": "github",
                "redirect_uri": req.redirect_uri,
                "state": secrets.token_urlsafe(32),
                "scopes": ["repo", "read:user", "offline_access"],
            }
        )
        logger.info(f"Connected Accounts initiate response received (status={response.status_code})")

        if response.status_code not in (200, 201):
            logger.error(f"Connect failed: {response.status_code} - {response.text}")
            raise HTTPException(status_code=response.status_code, detail="Failed to initiate connection.")

        data = response.json()
        ticket = data.get("connect_params", {}).get("ticket")
        connect_uri = data.get("connect_uri")
        auth_session = data.get("auth_session")

        return {
            "auth_session": auth_session,
            "connect_url": f"{connect_uri}?ticket={ticket}",
        }

@app.post("/connect/complete")
async def connect_complete(req: CompleteRequest, request: Request, user=Depends(get_current_user)):
    """Completes GitHub connection for the authenticated user."""
    my_account_token = await get_my_account_token(request)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/complete",
            headers={
                "Authorization": f"Bearer {my_account_token}",
                "Content-Type": "application/json",
            },
            json={
                "auth_session": req.auth_session,
                "connect_code": req.connect_code,
                "redirect_uri": req.redirect_uri,
            }
        )
        logger.info(f"Connected Accounts complete response received (status={response.status_code})")

        if response.status_code not in (200, 201):
            logger.error(f"Complete failed: {response.status_code} - {response.text}")
            raise HTTPException(status_code=response.status_code, detail="Failed to complete connection.")

        log_audit_event("GITHUB_CONNECTED", "GitHub account connected to Token Vault")
        return {"message": "GitHub account successfully connected to Token Vault!"}

@app.get("/connect/status")
async def connect_status(request: Request, user=Depends(get_current_user)):
    """Check which accounts are currently connected."""
    my_account_token = await get_my_account_token(request)

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://{AUTH0_DOMAIN}/me/v1/connected-accounts/accounts",
            headers={"Authorization": f"Bearer {my_account_token}"},
        )
        return response.json()

@app.post("/act")
async def act_endpoint(req: ActRequest, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    # Rate limit: cap concurrent jobs to prevent API credit drain
    active_jobs = sum(1 for j in jobs.values() if j.get("status") == "running")
    if active_jobs >= MAX_CONCURRENT_JOBS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many concurrent scans. Maximum is {MAX_CONCURRENT_JOBS}. Please wait for a job to complete."
        )

    job_id = str(uuid.uuid4())
    store_job(job_id, {"status": "running"})
    refresh_token = user.get("refresh_token")
    background_tasks.add_task(run_agent, job_id, req, refresh_token)
    return {"job_id": job_id, "poll_url": f"/result/{job_id}"}

@app.get("/result/{job_id}")
def get_result(job_id: str, user=Depends(get_current_user)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "token_vault": "active" if _AUTH0_SDK_AVAILABLE else "mock-mode",
    }

@app.get("/audit")
def get_audit(user=Depends(get_current_user)):
    return {"total_events": len(AUDIT_LOG), "logs": list(AUDIT_LOG)[::-1]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("application:app", host="127.0.0.1", port=8000, reload=True)