from flask import Flask, request, jsonify, abort, render_template
import requests
import json
import os
import shutil
import asyncio
import uuid
from typing import Any, Dict
from util import clone_repo, run_trivy
import re
app = Flask(__name__)

REPO_REGEX = re.compile(r'^https?://github\.com/[^/]+/[^/]+$')

@app.route('/')
def index():
    return render_template("index.html")

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
        t1 = asyncio.to_thread(run_trivy, repo_path)
        results = await asyncio.gather(t1)
        return results[0]  # Extract the first (and only) result

    t_code, t_out = 0, {}
    try:
        t_code, t_out = asyncio.run(run_all())
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    merged: Dict[str, Any] = {
        "scan_id": str(uuid.uuid4()),
        "repo": repo,
        "ref": ref,
        "tool_exit_codes": {"trivy": t_code},
        "findings": {"trivy": t_out},
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
def healthz():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
