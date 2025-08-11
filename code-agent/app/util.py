import json, shutil, tempfile, subprocess
from pathlib import Path
from typing import Any, Tuple


def run_cmd(args: list[str], cwd: str | None=None, timeout: int=120) -> Tuple[int,str,str]:
    try:
        p=subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1,"", "timeout"
    


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

def run_gitleaks(repo_path: str) -> Tuple[int, Any]:
    cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--redact"]
    code, out, err = run_cmd(cmd, timeout=120)
    if code < 0: return code, {"error": err or "gitleaks timeout"}
    # gitleaks returns exit code 1 when leaks found; output is JSON in stdout
    try:
        return code, json.loads(out or "{}")
    except Exception:
        return code, {"raw": out, "stderr": err}
    

def run_semgrep(repo_path: str) -> Tuple[int, Any]:
    cmd = ["semgrep", "--json"]
    cmd += ["--config", "p/ci", repo_path]
    code, out, err = run_cmd(cmd, timeout=240)
    if code < 0: return code, {"error": err or "semgrep timeout"}
    try:
        return code, json.loads(out or "{}")
    except Exception:
        return code, {"raw": out, "stderr": err}


def run_bandit(repo_path: str) -> Tuple[int, Any]:
    cmd = ["bandit", "-r", repo_path, "-f", "json", "-q"]
    code, out, err = run_cmd(cmd, timeout=180)
    if code < 0: return code, {"error": err or "bandit timeout"}
    try: 
        return code, json.loads(out or "{}")
    except Exception:
        return code, {"raw": out, "stderr": err}
