from flask import Flask, request, jsonify, render_template
import os
import json
import requests
from typing import Any, Dict, List

app = Flask(__name__)

@app.get("/")
def index():
    return render_template("index.html")

# ---- Ollama config ----
LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-oss-20b")  # e.g., "qwen3:8b", "qwen2.5:7b", "llama3.1:8b"
LLM_URL = os.getenv("LLM_URL", "http://host.docker.internal:1234")
REQUEST_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "120"))  # seconds


def heuristic_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    findings = payload.get("findings", {})
    summary: Dict[str, Any] = {"risk_score": 0, "signals": [], "recommendations": []}

    # Simple scoring based on presence of critical/high vulns and leaks
    def count_severities(results: Dict[str, Any]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if not results:
            return counts
        for res in results.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                sev = (v.get("Severity") or "").upper()
                if sev in counts:
                    counts[sev] += 1
        return counts

    trivy = findings.get("trivy")
    trivy_counts = count_severities(trivy if isinstance(trivy, dict) else {})
    leaks = findings.get("gitleaks", {})
    has_leaks = bool(leaks.get("findings") or leaks.get("leaks") or leaks.get("Results"))

    score = 0
    score += trivy_counts["CRITICAL"] * 3 + trivy_counts["HIGH"] * 2 + trivy_counts["MEDIUM"]
    if has_leaks:
        score += 3
    summary["risk_score"] = min(10, score)

    if has_leaks:
        summary["signals"].append("Potential secrets detected in repository")
        summary["recommendations"].append("Rotate affected secrets and scrub history if necessary")
    if trivy_counts["CRITICAL"] or trivy_counts["HIGH"]:
        summary["signals"].append("High-severity vulnerabilities in dependencies or base image")
        summary["recommendations"].append("Upgrade packages/base image and apply vendor patches")

    # Always recommend CI policy gates
    summary["recommendations"].append("Add CI gates to block critical/high findings before deploy")
    return summary


# Updated to support OpenAI chat format and optional streaming
def generate(messages: Any, model: str = None, temperature: float = 0.2, stream: bool = False) -> str:
    model = model or LLM_MODEL
    url = f"{LLM_URL.rstrip('/')}/v1/chat/completions"

    # Coerce string prompts into OpenAI chat format
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": stream,
    }

    parts: List[str] = []
    with requests.post(url, json=payload, stream=stream, timeout=REQUEST_TIMEOUT) as r:
        r.raise_for_status()

        # Non-streaming: parse once
        if not stream:
            data = r.json()
            if "error" in data:
                raise RuntimeError(str(data["error"]))
            # OpenAI style
            try:
                return (data["choices"][0]["message"]["content"] or "").strip()
            except Exception:
                # Fallback: Ollama/other providers sometimes return a single 'response'
                if "response" in data:
                    return str(data["response"]).strip()
                raise

        # Streaming: handle OpenAI-style SSE and also Ollama-like JSON lines
        for raw_line in r.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip()
            # OpenAI SSE lines are prefixed with 'data: '
            if line.startswith("data:"):
                line = line[len("data:"):].strip()
            if line == "[DONE]":
                break
            try:
                chunk = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed chunks and keep going
                continue

            if "error" in chunk:
                raise RuntimeError(str(chunk["error"]))

            # OpenAI streaming delta
            try:
                choice = (chunk.get("choices") or [None])[0] or {}
                delta = choice.get("delta") or {}
                content_piece = delta.get("content") or choice.get("message", {}).get("content") or ""
                if content_piece:
                    parts.append(content_piece)
                    continue
            except Exception:
                pass

            # Ollama-like streaming
            if "response" in chunk:
                parts.append(str(chunk["response"]))
            if chunk.get("done"):
                break

    return "".join(parts).strip()


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}

    # Build the same style of prompt you used before
    prompt = (
        "You are a concise cybersecurity expert. Given the following scan results from code, "
        "containers, k8s and logs, summarize key risks, provide a 0-10 risk score, and list "
        "prioritized remediation steps.\n\n"
        f"JSON: {json.dumps(payload, ensure_ascii=False)[:60000]}\n"
    )

    try:
        text = generate(prompt, model=LLM_MODEL, temperature=0.2, stream=False)
        return jsonify({"llm_summary": text}), 200
    except Exception as e:
        # Fallback to heuristic if Ollama isn't reachable or errors
        return jsonify({"fallback": heuristic_analysis(payload), "error": str(e)}), 200


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    # Ensure you've pulled the model first, e.g.: `ollama pull qwen3:8b`
    app.run(host="0.0.0.0", port=5010)
