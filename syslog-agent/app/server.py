from flask import Flask, request, jsonify, render_template
import time
import re
from collections import deque, Counter
from typing import Dict, Any, List

app = Flask(__name__)

# In-memory log buffer and simple rules (demo)
LOG_BUFFER: deque = deque(maxlen=1000)
RULES: List[Dict[str, Any]] = [
    {"name": "sudo usage", "pattern": r"sudo[ :](?:\w+)", "severity": "MEDIUM"},
    {"name": "failed auth", "pattern": r"failed password|authentication failure", "severity": "HIGH"},
    {"name": "unexpected root", "pattern": r"user=root|uid=0", "severity": "HIGH"},
]

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/ingest")
def ingest():
    payload = request.get_json(silent=True) or {}
    # Accept single or list
    events = payload if isinstance(payload, list) else [payload]
    ts = time.time()
    for ev in events:
        LOG_BUFFER.append({"ts": ts, **ev})
    return jsonify({"accepted": len(events), "buffer_size": len(LOG_BUFFER)})

@app.get("/findings")
def findings():
    matches: List[Dict[str, Any]] = []
    for entry in list(LOG_BUFFER):
        msg = str(entry.get("message", ""))
        for rule in RULES:
            if re.search(rule["pattern"], msg, flags=re.IGNORECASE):
                matches.append({"rule": rule["name"], "severity": rule["severity"], "event": entry})
    # Simple anomaly: top talkers
    sources = [e.get("source", "unknown") for e in LOG_BUFFER]
    top_sources = Counter(sources).most_common(5)
    return jsonify({"matches": matches, "top_sources": top_sources})

@app.post("/rules")
def add_rule():
    rule = request.get_json(silent=True) or {}
    if not rule.get("name") or not rule.get("pattern"):
        return jsonify({"error": "name and pattern required"}), 400
    RULES.append({"name": rule["name"], "pattern": rule["pattern"], "severity": rule.get("severity", "LOW")})
    return jsonify({"ok": True, "count": len(RULES)})

@app.get("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003) 