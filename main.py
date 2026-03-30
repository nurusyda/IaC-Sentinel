import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from github import Github, GithubException   # pip install PyGithub

# LangChain & LangGraph
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

# Auth0 AI SDK
try:
    from auth0_ai_langchain.auth0_ai import Auth0AI
    from auth0_ai_langchain.token_vault import get_credentials_from_token_vault
    from auth0_ai.exceptions import ConsentRequiredError
except ImportError:
    # Fallback for local testing only - REMOVE before final submission
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
    secret_key="change-this-in-production-2026",
    session_cookie="iac_sentinel_session",
    https_only=False,
    max_age=3600 * 8,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

application = app  # Required for Elastic Beanstalk

# ── Auth0 Token Vault ─────────────────────────────────────────────────────
auth0_ai = Auth0AI()
with_github_vault = auth0_ai.with_token_vault(connection="github")

# ── Tools ─────────────────────────────────────────────────────────────────
def fetch_iac_files(repo_owner: str, repo_name: str) -> str:
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
            raise HTTPException(status_code=401, detail="Token Vault consent required or expired")
        raise

fetch_tool = StructuredTool.from_function(
    func=fetch_iac_files,
    name="fetch_iac_files",
    description="Fetch all Terraform/CloudFormation files recursively from GitHub.",
    args_schema={"repo_owner": str, "repo_name": str},
)
fetch_iac_tool = with_github_vault(fetch_tool)


def scan_iac_security_issues(code: str) -> str:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = f"""
Analyze this IaC for cloud security issues:
- Wildcard IAM permissions (*)
- Public S3 buckets
- Missing CloudTrail

Return clear list with severity and remediation.

Code:
{code[:4000]}
"""
    response = llm.invoke(prompt)
    log_audit_event("AI_SCAN", "Local analysis completed")
    return response.content

scan_tool = StructuredTool.from_function(
    func=scan_iac_security_issues,
    name="scan_iac_security_issues",
    description="Analyze IaC code for security issues.",
    args_schema={"code": str},
)


def create_fix_pr(repo_owner: str, repo_name: str, branch: str, title: str, body: str, files_to_change: list) -> str:
    try:
        credentials = get_credentials_from_token_vault()
        g = Github(credentials["access_token"])
        repo = g.get_repo(f"{repo_owner}/{repo_name}")
        
        base_sha = repo.get_branch(repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
        
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
        return f"PR creation failed: {str(e)}"

create_pr_tool = StructuredTool.from_function(
    func=create_fix_pr,
    name="create_fix_pr",
    description="Create PR with security fixes.",
    args_schema={"repo_owner": str, "repo_name": str, "branch": str, "title": str, "body": str, "files_to_change": list},
)
create_fix_pr_tool = with_github_vault(create_pr_tool)

# ── Agent ─────────────────────────────────────────────────────────────────
tools = [fetch_iac_tool, scan_tool, create_fix_pr_tool]
agent_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

system_prompt = """You are IaC Sentinel, a cloud security agent.
Workflow:
1. Fetch IaC files using fetch_iac_files
2. Analyze them with scan_iac_security_issues
3. If critical issues found, use create_fix_pr to open a fixing PR.
Be proactive and concise."""

agent_executor = create_react_agent(agent_llm, tools, state_modifier=system_prompt)

# ── Endpoints ─────────────────────────────────────────────────────────────
class ActRequest(BaseModel):
    repo_owner: str
    repo_name: str
    user_message: str = "Scan this repository for IaC security issues and fix critical problems."

@app.post("/act")
async def act_endpoint(req: ActRequest):
    try:
        context_msg = f"Target Repo: {req.repo_owner}/{req.repo_name}. User request: {req.user_message}"
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
    return {"total_events": len(AUDIT_LOG), "logs": AUDIT_LOG[::-1]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)   # Fixed: use "main:app"
