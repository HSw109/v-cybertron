from flask import Flask, request, jsonify, abort, render_template
import os, re, json, uuid, shutil, tempfile, subprocess, asyncio
from pathlib import Path
from typing import Dict, Any, Tuple, List

app = Flask(__name__)

REPO_REGEX = re.compile(r"^https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?$")


def run_cmd(args: List[str], cwd: str | None=None, timeout: int=120) -> Tuple[int,str,str]:
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def clone_repo(repo_url: str, ref: str="HEAD") -> Tuple[str,str]:
    tmpdir = tempfile.mkdtemp(prefix="scan-")
    repo_path = Path(tmpdir) / "repo"
    code, out, err = run_cmd(["git","clone","--depth","1", repo_url, str(repo_path)])
    if code != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(err or "git clone failed")
    if ref and ref != "HEAD":
        code, out, err = run_cmd(["git", "-C", str(repo_path), "checkout", ref])
        if code != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise RuntimeError(err or "git checkout failed")
    return tmpdir, str(repo_path)


def run_kubelinter(repo_path: str) -> Tuple[int, Any]:
    cmd = ["kube-linter", "lint", repo_path, "--format", "json"]
    code, out, err = run_cmd(cmd, timeout=180)
    if code < 0: return code, {"error": err or "kube-linter timeout"}
    try:
        return code, json.loads(out or "{}")
    except Exception:
        return code, {"raw": out, "stderr": err}


def run_opa(repo_path: str) -> Tuple[int, Any]:
    # Optional: evaluate example policy against manifests; if no policies, return empty
    policies_dir = Path(__file__).parent / "policies"
    if not policies_dir.exists():
        return 0, {"results": []}

    # Find YAML files
    manifest_files: List[str] = []
    for root, _, files in os.walk(repo_path):
        for f in files:
            if f.endswith(('.yml', '.yaml')):
                manifest_files.append(os.path.join(root, f))
    if not manifest_files:
        return 0, {"results": []}

    results: List[Dict[str, Any]] = []
    for mf in manifest_files:
        code, out, err = run_cmd(["opa", "eval", "-f", "json", "-d", str(policies_dir), "-i", mf, "data"], timeout=60)
        if code < 0:
            results.append({"file": mf, "error": err or "opa timeout"})
        else:
            try:
                results.append({"file": mf, "data": json.loads(out or "{}")})
            except Exception:
                results.append({"file": mf, "raw": out, "stderr": err})
    return 0, {"results": results}


@app.get("/")
def index():
    return render_template("index.html")

@app.post("/scan")
def scan():
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
        t1 = asyncio.to_thread(run_kubelinter, repo_path)
        t2 = asyncio.to_thread(run_opa, repo_path)
        return await asyncio.gather(t1, t2)

    kl_code, kl_out = 0, {}
    opa_code, opa_out = 0, {}
    try:
        (kl_code, kl_out), (opa_code, opa_out) = asyncio.run(run_all())
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    merged: Dict[str, Any] = {
        "scan_id": str(uuid.uuid4()),
        "repo": repo,
        "ref": ref,
        "tool_exit_codes": {"kube-linter": kl_code, "opa": opa_code},
        "findings": {"kube-linter": kl_out, "opa": opa_out},
    }

    llm_url = os.getenv("LLM_URL")
    if llm_url:
        try:
            import requests
            resp = requests.post(f"{llm_url.rstrip('/')}/analyze", json=merged, timeout=30)
            if resp.ok:
                merged["llm_analysis"] = resp.json()
            else:
                merged["llm_analysis_error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            merged["llm_analysis_error"] = str(e)

    return jsonify(merged)

@app.get("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002) 