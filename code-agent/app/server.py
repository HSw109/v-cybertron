from flask import Flask, render_template, jsonify, request, abort
import os, re, json, uuid, shutil, tempfile, subprocess, asyncio
from pathlib import Path
from typing import Dict, Any, Tuple
from util import run_gitleaks, run_semgrep, run_bandit, clone_repo
import requests

app = Flask(__name__)

REPO_REGEX = re.compile(r"^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?$")


@app.get("/")
def hello_world():
    return render_template('index.html')

@app.post("/scan")
def scan():
    """
    POST JSON: { "repo": "https://github.com/owner/repo.git", "ref": "main" (optional) }
    Returns JSON with each tool's output.
    """
    data = request.get_json(silent=True) or {}
    repo = (data.get("repo") or "").strip()
    ref  = (data.get("ref") or "HEAD").strip() or "HEAD"
    if not REPO_REGEX.match(repo):
        return abort(400, description="Invalid or disallowed repo URL")

    try:
        tmpdir, repo_path = clone_repo(repo, ref)
    except RuntimeError as e:
        return abort(400, description=str(e))

    async def run_all():
        t1 = asyncio.to_thread(run_gitleaks, repo_path)
        t2 = asyncio.to_thread(run_semgrep,  repo_path)
        t3 = asyncio.to_thread(run_bandit,   repo_path)
        return await asyncio.gather(t1, t2, t3)

    g_code, g_out = 0, {}
    s_code, s_out = 0, {}
    b_code, b_out = 0, {}
    try:
        (g_code, g_out), (s_code, s_out), (b_code, b_out) = asyncio.run(run_all())
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    merged: Dict[str, Any] = {
        "scan_id": str(uuid.uuid4()),
        "repo": repo,
        "ref": ref,
        "tool_exit_codes": {"gitleaks": g_code, "semgrep": s_code, "bandit": b_code},
        "findings": {"gitleaks": g_out, "semgrep": s_out, "bandit": b_out},
    }

    # Optional: send to LLM analyzer if configured
    llm_url = os.getenv("LLM_URL")
    if llm_url:
        try:
            resp = requests.post(f"{llm_url.rstrip('/')}/analyze", json=merged, timeout=30)
            if resp.ok:
                merged["llm_analysis"] = resp.json()
            else:
                merged["llm_analysis_error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            merged["llm_analysis_error"] = str(e)

    return jsonify(merged)

@app.route("/healthz")
def healthz(): return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)