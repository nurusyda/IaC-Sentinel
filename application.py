import os
import logging
import sys
import subprocess
import json
import warnings
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Dict

# ── 1. INITIALIZE LOGGING (Once and for all) ──────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Auth0 AI SDK Handling (Corrected Import Paths) ───────────────────────
try:
    # Import the main class
    from auth0_ai_langchain.auth0_ai import Auth0AI
    
    # ✅ FIX: Import from token_vault, not auth0_ai
    from auth0_ai_langchain.token_vault import get_credentials_from_token_vault
    
    # Try to find ConsentRequiredError (try multiple possible locations)
    try:
        from auth0_ai_langchain.exceptions import ConsentRequiredError
    except ImportError:
        try:
            from auth0_ai.exceptions import ConsentRequiredError
        except ImportError:
            # Last resort fallback
            class ConsentRequiredError(Exception):
                def __init__(self, connection: str, authorization_url: str = None):
                    self.connection = connection
                    self.authorization_url = authorization_url

    _AUTH0_SDK_AVAILABLE = True
    logger.info("🚀 AUTH0 SDK LOADED: Token Vault is active.")

except ImportError as e:
    _AUTH0_SDK_AVAILABLE = False
    logger.warning(f"⚠️ Auth0 SDK failed to load (using mock-mode): {e}")
    
    # Fallback Mock Classes
    class ConsentRequiredError(Exception):
        def __init__(self, connection: str, authorization_url: str = None):
            self.connection = connection
            self.authorization_url = authorization_url

    class Auth0AI:
        def with_token_vault(self, connection: str):
            return lambda func: func

    def get_credentials_from_token_vault():
        warnings.warn("Using mock Auth0 credentials", RuntimeWarning)
        return {"access_token": "mock_token"}

# ── 3. CORE IMPORTS ───────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException
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

# ── CONFIG ────────────────────────────────────────────────────────────────
MAX_IAC_FILES = 15
AUTH0_URL = os.environ.get("AUTH0_GITHUB_AUTHORIZE_URL", "https://your-tenant.auth0.com/authorize")

# ── Startup Validation & App Config ───────────────────────────────────────
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY:
    raise RuntimeError("SESSION_SECRET_KEY environment variable is required")

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
    https_only=os.environ.get("ENVIRONMENT") == "production",
    max_age=3600 * 8,
)

ALLOWED_ORIGINS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False, # Set to False when using "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

application = app  # Required for Elastic Beanstalk

# ── Auth0 Token Vault ─────────────────────────────────────────────────────
auth0_ai = Auth0AI()
with_github_vault = auth0_ai.with_token_vault(
    connection="github",
    scopes=["repo", "read:user"],
)

# ── Tool Schemas (Pydantic) ───────────────────────────────────────────────
class FetchIacFilesArgs(BaseModel):
    repo_owner: str = Field(description="GitHub repository owner")
    repo_name: str = Field(description="GitHub repository name")

class ScanIacArgs(BaseModel):
    code: str = Field(description="IaC code to scan")

class ProposeFixArgs(BaseModel):
    repo_owner: str
    repo_name: str
    branch: str
    title: str
    body: str
    files_to_change: list

def propose_fix_pr(repo_owner: str, repo_name: str, branch: str, title: str, body: str, files_to_change: list) -> str:
    """Hardcoded to ALWAYS be a dry run. The AI cannot change this."""
    return create_fix_pr(
        repo_owner=repo_owner, repo_name=repo_name, branch=branch,
        title=title, body=body, files_to_change=files_to_change,
        dry_run=True  # Enforced
    )

# Use this tool in your 'tools' list instead
propose_fix_tool = StructuredTool.from_function(
    func=propose_fix_pr,
    name="propose_fix_pr",
    description="Preview security fixes. Does NOT create a real PR.",
    args_schema=ProposeFixArgs,
    handle_tool_errors=False,
)

# ── Tool 1: Fetch IaC Files ───────────────────────────────────────────────
@with_github_vault
def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
    try:
        credentials = get_credentials_from_token_vault()
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        iac_files = []
        contents = repo.get_contents("")
        
        # Capped at MAX_IAC_FILES for scalability
        while contents and len(iac_files) < MAX_IAC_FILES:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            elif file_content.name.endswith((".tf", ".yaml", ".yml", ".json")):
                try:
                    decoded = file_content.decoded_content.decode("utf-8")
                    iac_files.append(f"--- Path: {file_content.path} ---\n{decoded}")
                except Exception as e:
                    logger.warning(f"Failed to decode {file_content.path}, skipping. Error: {e}")

        log_audit_event("FETCH_IAC", f"Retrieved {len(iac_files)} files", f"{repo_owner}/{repo_name}")
        return "\n\n".join(iac_files) if iac_files else "No IaC files found."

    except GithubException as e:
        if e.status == 401:
            raise ConsentRequiredError(
                connection="github", 
                authorization_url=AUTH0_URL 
            ) from e
        raise

fetch_iac_tool = StructuredTool.from_function(
    func=fetch_iac_files,
    name="fetch_iac_files",
    description="Fetch all Terraform/CloudFormation files recursively from a GitHub repository.",
    args_schema=FetchIacFilesArgs,
    handle_tool_errors=False,
)

# ── Tool 2: Scan IaC Security Issues ─────────────────────────────────────
def scan_iac_security_issues(code: str) -> str:
    checkov_results = ""
    try:
        import tempfile, os, re
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            parts = re.split(r'---\s*Path:\s*(.+?)\s*---', code)
            if len(parts) > 1:
                for i in range(1, len(parts), 2):
                    rel_path = parts[i].strip()
                    content = parts[i+1].strip()
                    
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

            result = subprocess.run(
                ["checkov", "--directory", tmp_dir, "--output", "json", "--quiet"],
                capture_output=True, text=True, timeout=30
            )

        if result.stdout:
            data = json.loads(result.stdout)
            failed = data.get("results", {}).get("failed_checks", [])
            if failed:
                checkov_results = "\n".join(
                    f"[{c['check_id']}] {c['check_type']} - {c['resource']} - {c['check_result']['result']}"
                    for c in failed[:10]
                )
    except Exception as e:
        checkov_results = f"Checkov unavailable: {e}"

    # Direct DeepSeek Configuration for the Scanner
    llm = ChatOpenAI(
        model="deepseek-chat", 
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
        temperature=0
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
    args_schema=ScanIacArgs, # <-- Fixed Schema
)

# ── Tool 3: Create Fix PR (with dry_run safety) ───────────────────────────
@with_github_vault
def create_fix_pr(
    repo_owner: str,
    repo_name: str,
    branch: str,
    title: str,
    body: str,
    files_to_change: list,
    dry_run: bool = True  
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
                # <-- Fixed: Handle both update and create
                existing = repo.get_contents(f["path"], ref=branch)
                repo.update_file(
                    path=f["path"],
                    message=f"Security fix: {title}",
                    content=f["content"],
                    sha=existing.sha,
                    branch=branch
                )
            except GithubException as e:
                if e.status == 404:
                    repo.create_file(
                        path=f["path"],
                        message=f"Security fix: {title}",
                        content=f["content"],
                        branch=branch
                    )
                else:
                    raise

        pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
        log_audit_event("CREATE_PR", f"PR #{pr.number} created", f"{repo_owner}/{repo_name}")
        return f"Success! PR created: {pr.html_url}"

    except Exception as e:
        if ref_created and repo is not None: # <-- Fixed cleanup bug
            try:
                repo.get_git_ref(f"heads/{branch}").delete()
            except Exception:
                pass 
        return f"PR creation failed (rolled back branch): {str(e)}"



# ── Agent ─────────────────────────────────────────────────────────────────
# create_fix_pr exists but is intentionally NOT in tools.
# propose_fix_tool wraps it with dry_run=True enforced.
tools = [fetch_iac_tool, scan_tool, propose_fix_tool]

# Direct DeepSeek Configuration for the Agent Brain
agent_llm = ChatOpenAI(
    model="deepseek-chat", 
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
    temperature=0
)

system_prompt = """You are IaC Sentinel, an elite DevSecOps AI security agent.

Your workflow:
1. Use fetch_iac_files to retrieve infrastructure code.
2. Use scan_iac_security_issues to analyze the code.
3. If HIGH severity issues are found, use propose_fix_pr to suggest fixes. 
   Explain that this is a preview and requires manual review."""

agent_executor = create_react_agent(agent_llm, tools, state_modifier=system_prompt)

# ── Endpoints ─────────────────────────────────────────────────────────────
class ActRequest(BaseModel):
    repo_owner: str
    repo_name: str
    user_message: str = "Scan this repository for IaC security issues and propose fixes."

@app.post("/act")
async def act_endpoint(req: ActRequest):
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. Request: {req.user_message}"
        result = await agent_executor.ainvoke({"messages": [HumanMessage(content=context_msg)]})

        # 🔍 CHECK: Did the AI "trap" a consent error in its history?
        for msg in result["messages"]:
            # If the Auth0 SDK raised an error, it often appears in the Tool messages
            if hasattr(msg, "content") and "ConsentRequiredError" in str(msg.content):
                # If we find it, manually re-raise it so the 'except' block below catches it
                raise ConsentRequiredError(connection="github", authorization_url=AUTH0_URL)

        return {
            "response": result["messages"][-1].content,
            "recent_audit": list(AUDIT_LOG)[-5:]
        }

    except ConsentRequiredError as e:
        # 🚀 THE GOAL: This sends the 403 + Login Link to your Swagger UI
        raise HTTPException(
            status_code=403,
            detail={
                "error": "consent_required",
                "connection": e.connection,
                "authorization_url": e.authorization_url
            }
        ) from e
    except Exception as e:
        logger.error(f"Agent error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.get("/health")
def health():
    return {
        "status": "healthy", 
        "token_vault": "active" if _AUTH0_SDK_AVAILABLE else "mock-mode"
    }

@app.get("/audit")
def get_audit():
    return {"total_events": len(AUDIT_LOG), "logs": list(AUDIT_LOG)[::-1]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("application:app", host="0.0.0.0", port=8000, reload=True)