import os
import shutil
import logging
import sys
import subprocess
import json
import warnings
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Dict, Any

# ── 1. INITIALIZE LOGGING (Once and for all) ──────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── 2. AUTH0 AI SDK Handling (Corrected Import Paths) ────────────────────
try:
    from auth0_ai_langchain.auth0_ai import Auth0AI
    from auth0_ai_langchain.token_vault import get_credentials_from_token_vault

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
    _AUTH0_SDK_AVAILABLE = False
    logger.warning(f"⚠️ Auth0 SDK failed to load (using mock-mode): {e}")

    class ConsentRequiredError(Exception):
        def __init__(self, connection: str, authorization_url: str = None):
            self.connection = connection
            self.authorization_url = authorization_url

    class Auth0AI:
        def with_token_vault(self, connection: str, scopes: list = None, **kwargs):
            return lambda func: func

    def get_credentials_from_token_vault():
        warnings.warn("Using mock Auth0 credentials", RuntimeWarning)
        return {"access_token": "mock_token"}

# ── 3. CORE IMPORTS ───────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from github import Github, GithubException
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage
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

AUTH0_URL = os.environ.get("AUTH0_GITHUB_AUTHORIZE_URL")
if not AUTH0_URL and os.environ.get("ENVIRONMENT") == "production":
    raise RuntimeError("AUTH0_GITHUB_AUTHORIZE_URL is required in production")
AUTH0_URL = AUTH0_URL or "https://your-tenant.auth0.com/authorize"

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY:
    raise RuntimeError("SESSION_SECRET_KEY environment variable is required")

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
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

application = app  # Required for Elastic Beanstalk

# ── 6.5 BACKGROUND JOBS STORE ─────────────────────────────────────────────
jobs: Dict[str, Any] = {}

# ── 7. AUTH0 TOKEN VAULT ──────────────────────────────────────────────────
auth0_ai = Auth0AI()
with_github_vault = auth0_ai.with_token_vault(
    connection="github",
    scopes=["repo", "read:user"],
)

# ── 8. TOOL SCHEMAS (Pydantic) ────────────────────────────────────────────
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

class ProposeFixArgs(BaseModel):
    repo_owner: str
    repo_name: str
    branch: str
    title: str
    body: str
    files_to_change: list

# ── 9. TOOL 3: CREATE FIX PR (defined first; referenced by propose_fix_pr) ──
def create_fix_pr(
    repo_owner: str,
    repo_name: str,
    branch: str,
    title: str,
    body: str,
    files_to_change: list,
    dry_run: bool = True,
) -> str:
    if dry_run:
        suggestion = f"[DRY RUN] Would create PR '{title}' on {repo_owner}/{repo_name}\n\n"
        suggestion += "Proposed changes:\n"
        for f in files_to_change:
            suggestion += f"\n--- {f['path']} ---\n{f['content']}\n"
        log_audit_event("DRY_RUN_PR", f"Suggested fix for {repo_owner}/{repo_name}")
        return suggestion

    repo = None
    ref_created = False
    try:
        credentials = get_credentials_from_token_vault()
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        base_sha = repo.get_branch(repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
        ref_created = True

        for f in files_to_change:
            try:
                existing = repo.get_contents(f["path"], ref=branch)
                repo.update_file(
                    path=f["path"],
                    message=f"Security fix: {title}",
                    content=f["content"],
                    sha=existing.sha,
                    branch=branch,
                )
            except GithubException as e:
                if e.status == 404:
                    repo.create_file(
                        path=f["path"],
                        message=f"Security fix: {title}",
                        content=f["content"],
                        branch=branch,
                    )
                else:
                    raise

        pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
        log_audit_event("CREATE_PR", f"PR #{pr.number} created", f"{repo_owner}/{repo_name}")
        return f"Success! PR created: {pr.html_url}"

    except Exception as e:
        if ref_created and repo is not None:
            try:
                repo.get_git_ref(f"heads/{branch}").delete()
            except Exception as cleanup_err:
                logger.warning(f"Failed to cleanup branch {branch}: {cleanup_err}")
        return f"PR creation failed (rolled back branch): {str(e)}"

# ── 10. PROPOSE FIX TOOL (dry-run wrapper; always dry_run=True) ───────────
def propose_fix_pr(
    repo_owner: str,
    repo_name: str,
    branch: str,
    title: str,
    body: str,
    files_to_change: list,
) -> str:
    """Hardcoded to ALWAYS be a dry run. The AI cannot change this."""
    return create_fix_pr(
        repo_owner=repo_owner,
        repo_name=repo_name,
        branch=branch,
        title=title,
        body=body,
        files_to_change=files_to_change,
        dry_run=True,  # Enforced — never passed from outside
    )

propose_fix_tool = StructuredTool.from_function(
    func=propose_fix_pr,
    name="propose_fix_pr",
    description="Preview security fixes. Does NOT create a real PR.",
    args_schema=ProposeFixArgs,
    handle_tool_errors=False,
)

# ── 11. TOOL 1: FETCH IAC FILES ───────────────────────────────────────────
def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
    try:
        credentials = get_credentials_from_token_vault()
        logger.info(f"Got credentials: {list(credentials.keys())}")
        logger.info(f"Token preview: {credentials.get('access_token', '')[:10]}...")
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        iac_files = []

        # get_contents("") can return a single ContentFile instead of a list
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
        return "\n\n".join(iac_files) if iac_files else "No IaC files found."

    except GithubException as e:
        if e.status == 401:
            raise ConsentRequiredError(
                connection="github",
                authorization_url=AUTH0_URL,
            ) from e
        raise

fetch_iac_tool = with_github_vault(
    StructuredTool.from_function(
        func=fetch_iac_files,
        name="fetch_iac_files",
        description="Fetch all Terraform/CloudFormation files recursively from a GitHub repository.",
        args_schema=FetchIacFilesArgs,
        handle_tool_errors=False,
    )
)
logger.info(f"fetch_iac_tool type: {type(fetch_iac_tool)}")
logger.info(f"fetch_iac_tool name: {getattr(fetch_iac_tool, 'name', 'NO NAME')}")

# ── 12. TOOL 2: SCAN IAC SECURITY ISSUES ─────────────────────────────────
def scan_iac_security_issues(code: str) -> str:
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

                    # Prevent path traversal and preserve directory structure
                    normalized = os.path.normpath(rel_path).lstrip("/\\")

                    if normalized.startswith("..") or ".." in normalized:
                        logger.warning(f"Blocked path traversal attempt: {rel_path}")
                        continue

                    target_path = os.path.join(tmp_dir, normalized)

                    # Final security check: ensure it didn't resolve outside tmp_dir
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
                result = subprocess.run(
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

    # Direct DeepSeek Configuration for the Scanner
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

    response = llm.invoke(prompt)
    log_audit_event("AI_SCAN", "Hybrid Checkov + LLM analysis completed")
    return response.content

scan_tool = StructuredTool.from_function(
    func=scan_iac_security_issues,
    name="scan_iac_security_issues",
    description="Analyze IaC code for security issues using rule-based scanning + LLM explanation.",
    args_schema=ScanIacArgs,
)

# ── 13. AGENT ─────────────────────────────────────────────────────────────
# create_fix_pr exists but is intentionally NOT in tools.
# propose_fix_tool wraps it with dry_run=True enforced.
tools = [fetch_iac_tool, scan_tool, propose_fix_tool]

agent_llm = ChatOpenAI(
    model="deepseek-chat",
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
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

# ── 14. ENDPOINTS ─────────────────────────────────────────────────────────
class ActRequest(BaseModel):
    repo_owner: str
    repo_name: str
    user_message: str = "Scan this repository for IaC security issues and propose fixes."

async def run_agent(job_id: str, req: ActRequest):
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. Request: {req.user_message}"
        result = await agent_executor.ainvoke({"messages": [HumanMessage(content=context_msg)]})
        jobs[job_id] = {
            "status": "done",
            "response": result["messages"][-1].content,
            "recent_audit": list(AUDIT_LOG)[-5:],
        }
    except ConsentRequiredError as e:
        jobs[job_id] = {
            "status": "error",
            "error": "consent_required",
            "connection": e.connection,
            "authorization_url": e.authorization_url,
        }
    except Exception as e:
        logger.error(f"Agent error: {e}")
        jobs[job_id] = {"status": "error", "error": str(e)}

@app.post("/act")
async def act_endpoint(req: ActRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running"}
    background_tasks.add_task(run_agent, job_id, req)
    return {"job_id": job_id, "poll_url": f"/result/{job_id}"}

@app.get("/result/{job_id}")
def get_result(job_id: str):
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
def get_audit():
    return {"total_events": len(AUDIT_LOG), "logs": list(AUDIT_LOG)[::-1]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("application:app", host="127.0.0.1", port=8000, reload=True)