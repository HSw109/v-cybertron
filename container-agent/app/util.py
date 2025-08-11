import os, json, shutil, tempfile, subprocess
from pathlib import Path
from typing import Any, Tuple
import requests

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

def run_trivy(repo_path: str) -> Tuple[int, Any]:
    cmd = ["trivy", "fs", "--format", "json", "--output", "trivy-report.json", repo_path]
    code, out, err = run_cmd(cmd, timeout=120)
    if code < 0: return code, {"error": err or "trivy timeout"}
    
    ### Scan image
    img_names = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file == "Dockerfile":
                dockerfile_path = os.path.join(root, file)
                try:
                    with open(dockerfile_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.upper().startswith('FROM '):
                                # Extract image name from FROM instruction
                                # Handle cases like "FROM ubuntu:22.04", "FROM python:3.11-alpine AS builder"
                                parts = line.split()
                                if len(parts) >= 2:
                                    img_names.append(parts[1])  # Get the image name after FROM
                                    break
                except Exception:
                    continue  # Skip if can't read Dockerfile

    # If we found an image name, scan it with trivy
    img_results = {}
    for img_name in img_names:
        cmd_img = ["trivy", "image", "--format", "json", "--output", "trivy-report-img.json", img_name]
        code_img, out_img_raw, err_img = run_cmd(cmd_img, timeout=120)
        if code_img < 0:
            img_results[img_name] = {"error": err_img or "trivy timeout"}
        else:
            try:
                img_results[img_name] = json.loads(out_img_raw or "{}")
            except Exception:
                img_results[img_name] = {"raw": out_img_raw, "stderr": err_img}
            
    try:
        fs_results = json.loads(out or "{}")
        # Combine filesystem and image results
        combined_results = {
            "filesystem": fs_results,
            "images": img_results
        }
        return code, combined_results
    except Exception:
        return code, {"raw": out, "stderr": err, "images": img_results}