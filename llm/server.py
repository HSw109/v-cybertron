from flask import Flask, request, jsonify, render_template, Response, stream_with_context, make_response
import os, json, requests, time
from typing import Any, Dict, List
from util import _norm_text

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False  # ensure jsonify writes UTF-8, not \u escapes

@app.get("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Content-Type"] = "text/html"
    return resp

# ---- Ollama / OpenAI-compatible config ----
LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-oss-20b")
LLM_URL = os.getenv("LLM_URL", "http://host.docker.internal:1234")
REQUEST_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "120"))  # seconds


def heuristic_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Works whether 'findings' is top-level or nested."""
    root = payload.get("findings")
    findings = root if isinstance(root, dict) else payload

    summary: Dict[str, Any] = {"risk_score": 0, "signals": [], "recommendations": []}

    def count_severities(trivy_block: Dict[str, Any]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if not isinstance(trivy_block, dict):  # be defensive
            return counts
        for res in (trivy_block.get("Results") or []):
            for v in (res.get("Vulnerabilities") or []):
                sev = (v.get("Severity") or "").upper()
                if sev in counts:
                    counts[sev] += 1
        return counts

    trivy_counts = count_severities(findings.get("trivy", {}))
    leaks = findings.get("gitleaks", {})
    has_leaks = bool(
        (isinstance(leaks, dict))
        and (leaks.get("findings") or leaks.get("leaks") or leaks.get("Results"))
    )

    score = (
        trivy_counts["CRITICAL"] * 3
        + trivy_counts["HIGH"] * 2
        + trivy_counts["MEDIUM"]
        + (3 if has_leaks else 0)
    )
    summary["risk_score"] = min(10, score)

    if has_leaks:
        summary["signals"].append("Potential secrets detected in repository")
        summary["recommendations"].append("Rotate affected secrets and scrub history if necessary")
    if trivy_counts["CRITICAL"] or trivy_counts["HIGH"]:
        summary["signals"].append("High-severity vulnerabilities in dependencies or base image")
        summary["recommendations"].append("Upgrade packages/base image and apply vendor patches")

    summary["recommendations"].append("Add CI gates to block critical/high findings before deploy")
    return summary


def _chat_payload(messages: Any, model: str, temperature: float, stream: bool):
    # Accept string or OpenAI-style messages
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    return {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": stream,
    }


def _parse_stream_line(line: str) -> str:
    """
    Accepts OpenAI-style 'data: {...}' SSE chunks or Ollama JSON lines and
    returns only the new content piece ('' if none).
    """
    s = line.strip()
    if not s:
        return ""
    if s.startswith("data:"):
        s = s[len("data:"):].strip()
    if s == "[DONE]":
        return ""

    try:
        j = json.loads(s)
    except json.JSONDecodeError:
        return ""

    # OpenAI streaming delta
    try:
        choice = (j.get("choices") or [None])[0] or {}
        delta = choice.get("delta") or {}
        piece = delta.get("content") or choice.get("message", {}).get("content") or ""
        if piece:
            return str(piece)
    except Exception:
        pass

    # Ollama-like
    if "response" in j:
        return str(j["response"])

    return ""


def stream_generate(messages: Any, model: str, temperature: float):
    """
    Generator yielding text pieces as they arrive from the LLM server.
    """
    payload = _chat_payload(messages, model, temperature, stream=True)
    url = f"{LLM_URL.rstrip('/')}/v1/chat/completions"

    with requests.post(url, json=payload, stream=True, timeout=REQUEST_TIMEOUT) as r:
        r.raise_for_status()
        for raw in r.iter_lines(decode_unicode=False):  # get BYTES
            if not raw:
                continue
            try:
                line = raw.decode("utf-8")              # strict UTF-8
            except UnicodeDecodeError:
                line = raw.decode("utf-8", "replace")  # keep stream alive on odd bytes
            piece = _parse_stream_line(line)
            if piece:
                # optional: normalize fancy punctuation to ASCII (see §3)
                piece = _norm_text(piece)
                yield piece

def generate_once(messages: Any, model: str, temperature: float) -> str:
    """
    Non-streaming single response (for /analyze).
    """
    payload = _chat_payload(messages, model, temperature, stream=False)
    url = f"{LLM_URL.rstrip('/')}/v1/chat/completions"

    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(str(data["error"]))
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        if "response" in data:
            return str(data["response"]).strip()
        raise


def build_prompt(payload: Dict[str, Any]) -> str:
    return (
        "You are a concise cybersecurity expert. Given the following scan results from code, "
        "containers, k8s and logs, summarize key risks, provide a 0-10 risk score, and list "
        "prioritized remediation steps. Use markdown (headings, tables, checklists) and keep it compact.\n\n"
        
        f"JSON: {json.dumps(payload, ensure_ascii=False)[:60000]}\n"
    )


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    prompt = build_prompt(payload)
    try:
        text = generate_once(prompt, model=LLM_MODEL, temperature=0.2)
        # ensure explicit charset
        resp = app.response_class(
            response=json.dumps({"llm_summary": text}, ensure_ascii=False),
            mimetype="application/json; charset=utf-8",
        )
        return resp, 200
    except Exception as e:
        resp = app.response_class(
            response=json.dumps({"fallback": heuristic_analysis(payload), "error": str(e)}, ensure_ascii=False),
            mimetype="application/json; charset=utf-8",
        )
        return resp, 200



@app.post("/analyze/stream")
def analyze_stream():
    # Streaming response via text/event-stream (SSE-like payloads over POST)
    payload = request.get_json(silent=True) or {}
    prompt = build_prompt(payload)

    def event_stream():
        # helpful start event + heartbeat
        yield "event: start\ndata: {}\n\n"
        last_beat = time.time()

        try:
            acc = []
            for piece in stream_generate(prompt, model=LLM_MODEL, temperature=0.2):
                acc.append(piece)
                data = json.dumps({"delta": piece})
                yield f"data: {data}\n\n"
                # heartbeat every ~10s to keep proxies alive
                if time.time() - last_beat > 10:
                    yield ": keep-alive\n\n"
                    last_beat = time.time()
            final = json.dumps({"final": "".join(acc)})
            yield f"event: done\ndata: {final}\n\n"
        except Exception as e:
            err = json.dumps({"error": str(e)})
            yield f"event: error\ndata: {err}\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream, charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",    # nginx
            "Connection": "keep-alive",
        },
    )


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010)
