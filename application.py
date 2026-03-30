import os
import logging
import sys
import subprocess
import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from github import Github, GithubException

from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from dotenv import load_dotenv
load_dotenv()

try:
    from auth0_ai_langchain.auth0_ai import Auth0AI
    from auth0_ai_langchain.token_vault import get_credentials_from_token_vault
    from auth0_ai.exceptions import ConsentRequiredError
except ImportError:
    class ConsentRequiredError(Exception):
        def __init__(self, connection: str, authorization_url: str = None):
            self.connection = connection
            self.authorization_url = authorization_url

    class Auth0AI:
        def with_token_vault(self, connection: str):
            def decorator(func): return func
            return decorator

    def get_credentials_from_token_vault():
        return {"access_token": "mock_token"}

# ── Logging & Audit ───────────────────────────────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

AUDIT_LOG: List[Dict] = []

def log_audit_event(action: str, details: str = "", target: str = "Internal"):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "details": details,
        "target": target,
        "source": "Token Vault",
    }
    AUDIT_LOG.append(event)
    if len(AUDIT_LOG) > 50:
        AUDIT_LOG.pop(0)
    logger.info(f"AUDIT: {event}")

# ── Lifespan ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IaC Sentinel starting up with Auth0 Token Vault...")
    yield
    logger.info("IaC Sentinel shutting down.")

app = FastAPI(
    title="IaC Sentinel",
    description="AI-powered IaC security scanner using Auth0 Token Vault for secure GitHub delegation.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET_KEY"],  
    session_cookie="iac_sentinel_session",
    https_only=os.environ.get("ENVIRONMENT") == "production", 
    max_age=3600 * 8,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

application = app  # Required for Elastic Beanstalk

# ── Auth0 Token Vault ─────────────────────────────────────────────────────
auth0_ai = Auth0AI()
with_github_vault = auth0_ai.with_token_vault(connection="github")

# ── Tool 1: Fetch IaC Files ───────────────────────────────────────────────
# Decorator on the function FIRST, then wrap in StructuredTool
@with_github_vault
def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
    """Fetches all .tf and .yaml files recursively from the GitHub repository."""
    try:
        credentials = get_credentials_from_token_vault()
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        iac_files = []
        contents = repo.get_contents("")

        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            elif file_content.name.endswith((".tf", ".yaml", ".yml", ".json")):
                try:
                    decoded = file_content.decoded_content.decode("utf-8")
                    iac_files.append(f"--- Path: {file_content.path} ---\n{decoded}")
                except Exception:
                    pass

        log_audit_event("FETCH_IAC", f"Retrieved {len(iac_files)} files", f"{repo_owner}/{repo_name}")
        return "\n\n".join(iac_files) if iac_files else "No IaC files found."

    except GithubException as e:
        if e.status == 401:
            # Raise the specific error that triggers the Auth0 re-auth flow!
            raise ConsentRequiredError(
                connection="github", 
                authorization_url="https://your-tenant.auth0.com/authorize" # Update if you have your exact Auth0 URL
            )
        raise

fetch_iac_tool = StructuredTool.from_function(
    func=fetch_iac_files,
    name="fetch_iac_files",
    description="Fetch all Terraform/CloudFormation files recursively from a GitHub repository. Always use this first.",
    args_schema={"repo_owner": str, "repo_name": str},
)

# ── Tool 2: Scan IaC Security Issues ─────────────────────────────────────
def scan_iac_security_issues(code: str) -> str:
    """Runs Checkov for rule-based scanning, then uses LLM for remediation explanation."""

    checkov_results = ""
    try:
        import tempfile, os, re
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Split the giant string back into individual files based on our header format
            parts = re.split(r'---\s*Path:\s*(.+?)\s*---', code)
            
            if len(parts) > 1:
                for i in range(1, len(parts), 2):
                    rel_path = parts[i].strip()
                    content = parts[i+1].strip()
                    # Flatten the structure into the temp dir for a quick scan
                    safe_name = os.path.basename(rel_path) or f"file_{i}.tf"
                    with open(os.path.join(tmp_dir, safe_name), "w", encoding="utf-8") as f:
                        f.write(content)
            else:
                # Fallback if no headers found
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

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
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
    args_schema={"code": str},
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
    dry_run: bool = True  # Safe by default — set False to actually create PR
) -> str:
    """Creates a PR with security fixes, or returns suggested diff in dry_run mode."""

    if dry_run:
        suggestion = f"[DRY RUN] Would create PR '{title}' on {repo_owner}/{repo_name}\n\n"
        suggestion += "Proposed changes:\n"
        for f in files_to_change:
            suggestion += f"\n--- {f['path']} ---\n{f['content']}\n"
        log_audit_event("DRY_RUN_PR", f"Suggested fix for {repo_owner}/{repo_name}")
        return suggestion

    ref_created = False
    try:
        credentials = get_credentials_from_token_vault()
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        base_sha = repo.get_branch(repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
        ref_created = True # Track that the branch exists!

        for f in files_to_change:
            repo.update_file(
                path=f["path"],
                message=f"Security fix: {title}",
                content=f["content"],
                sha=repo.get_contents(f["path"]).sha,
                branch=branch
            )

        pr = repo.create_pull(title=title, body=body, head=branch, base=repo.default_branch)
        log_audit_event("CREATE_PR", f"PR #{pr.number} created", f"{repo_owner}/{repo_name}")
        return f"Success! PR created: {pr.html_url}"

    except Exception as e:
        # CLEANUP: Delete the stray branch if the PR process failed
        if ref_created:
            try:
                repo.get_git_ref(f"heads/{branch}").delete()
            except Exception:
                pass # Ignore errors during cleanup
        return f"PR creation failed (rolled back branch): {str(e)}"

create_fix_pr_tool = StructuredTool.from_function(
    func=create_fix_pr,
    name="create_fix_pr",
    description=(
        "Create a GitHub PR with security fixes, or suggest the fix in dry_run mode. "
        "Use dry_run=True (default) to safely preview changes. "
        "files_to_change is a list of dicts with 'path' and 'content'."
    ),
    args_schema={
        "repo_owner": str,
        "repo_name": str,
        "branch": str,
        "title": str,
        "body": str,
        "files_to_change": list,
        "dry_run": bool,
    },
)

# ── Agent ─────────────────────────────────────────────────────────────────
tools = [fetch_iac_tool, scan_tool, create_fix_pr_tool]
agent_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

system_prompt = """You are IaC Sentinel, an elite DevSecOps AI security agent.

Your workflow:
1. Use fetch_iac_files to retrieve all infrastructure code from the target repository.
2. Use scan_iac_security_issues to analyze the fetched code for vulnerabilities.
3. If HIGH severity issues are found, use create_fix_pr with dry_run=True to propose fixes.
   Only use dry_run=False if the user explicitly requests a real PR.

Be concise. Always cite the specific resource and line causing the issue.
In production, every token exchange is logged for SOC audit purposes."""

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
        result = agent_executor.invoke({"messages": [HumanMessage(content=context_msg)]})

        return {
            "response": result["messages"][-1].content,
            "recent_audit": AUDIT_LOG[-5:]
        }

    except ConsentRequiredError as e:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "consent_required",
                "message": "GitHub consent required via Auth0 Token Vault.",
                "authorization_url": getattr(e, "authorization_url", None)
            }
        )
    except Exception as e:
        logger.error(f"Agent error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "healthy", "token_vault": "active"}

@app.get("/audit")
def get_audit():
    # In production: replace AUDIT_LOG with CloudWatch/CloudTrail queries
    return {"total_events": len(AUDIT_LOG), "logs": AUDIT_LOG[::-1]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("application:app", host="0.0.0.0", port=8000, reload=True)