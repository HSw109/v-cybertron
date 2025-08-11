from flask import Flask, request, jsonify, render_template
import os
import requests

app = Flask(__name__)

CODE_URL = os.getenv("CODE_AGENT_URL", "http://code-agent:5000")
CONT_URL = os.getenv("CONTAINER_AGENT_URL", "http://container-agent:5001")
K8S_URL  = os.getenv("K8S_AGENT_URL", "http://k8s-agent:5002")
SYS_URL  = os.getenv("SYSLOG_AGENT_URL", "http://syslog-agent:5003")

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/scan/code")
def scan_code():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{CODE_URL}/scan", json=payload, timeout=120)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.post("/scan/container")
def scan_container():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{CONT_URL}/scan", json=payload, timeout=600)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.post("/scan/k8s")
def scan_k8s():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{K8S_URL}/scan", json=payload, timeout=300)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.post("/logs/ingest")
def logs_ingest():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{SYS_URL}/ingest", json=payload, timeout=30)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.get("/logs/findings")
def logs_findings():
    r = requests.get(f"{SYS_URL}/findings", timeout=30)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.get("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5080) 