from flask import Flask, request, jsonify
import os
import json
from typing import Any, Dict

try:
    from openai import OpenAI  # featherless-compatible client
except Exception:
    OpenAI = None

app = Flask(__name__)

LLM_BASE_URL = os.getenv("LLM_BASE_URL")
LLM_API_KEY  = os.getenv("LLM_API_KEY")
LLM_MODEL    = os.getenv("LLM_MODEL", "trendmicro-ailab/Llama-Primus-Reasoning")

client = None
if OpenAI and LLM_BASE_URL and LLM_API_KEY:
    try:
        client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
    except Exception:
        client = None


def heuristic_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    findings = payload.get("findings", {})
    summary: Dict[str, Any] = {"risk_score": 0, "signals": [], "recommendations": []}

    # Simple scoring based on presence of critical/high vulns and leaks
    def count_severities(results: Dict[str, Any]) -> Dict[str, int]:
        counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0}
        if not results: return counts
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
    if has_leaks: score += 3
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


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}

    if client:
        try:
            prompt = (
                "You are a cybersecurity expert. Given the following scan results from code, container, k8s and logs, "
                "summarize key risks, provide a 0-10 risk score, and list prioritized remediation steps.\n\n"
                f"JSON: {json.dumps(payload)[:60000]}\n"
            )
            resp = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "You are a concise cybersecurity assistant."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            text = resp.model_dump()["choices"][0]["message"]["content"]
            return jsonify({"llm_summary": text}), 200
        except Exception as e:
            # Fallback to heuristic
            return jsonify({"fallback": heuristic_analysis(payload), "error": str(e)}), 200

    # No client configured, heuristic only
    return jsonify({"fallback": heuristic_analysis(payload)}), 200


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010) 