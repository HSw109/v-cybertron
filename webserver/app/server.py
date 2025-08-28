from flask import Flask, request, jsonify, render_template, Response, stream_with_context
import os
import requests
import json
import time

app = Flask(__name__)

CODE_URL = os.getenv("CODE_AGENT_URL", "http://code-agent:5000")
CONT_URL = os.getenv("CONTAINER_AGENT_URL", "http://container-agent:5001")
K8S_URL  = os.getenv("K8S_AGENT_URL", "http://k8s-agent:5002")
SYS_URL  = os.getenv("SYSLOG_AGENT_URL", "http://syslog-agent:5003")
LLM_URL  = os.getenv("LLM_URL", "http://llm:5010")

@app.get("/")
def index():
    return render_template("dashboard.html")

# Agent page routes
@app.get("/agent/code")
def code_agent_page():
    return render_template("code_agent.html")

@app.get("/agent/container")
def container_agent_page():
    return render_template("container_agent.html")

@app.get("/agent/k8s")
def k8s_agent_page():
    return render_template("k8s_agent.html")

@app.get("/agent/syslog")
def syslog_agent_page():
    return render_template("syslog_agent.html")

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

# Streaming LLM analysis endpoints
@app.post("/scan/code/stream")
def scan_code_stream():
    payload = request.get_json(silent=True) or {}
    
    def event_stream():
        yield "event: start\ndata: {}\n\n"
        last_beat = time.time()
        
        try:
            # Step 1: Call code agent to perform actual security scan
            yield f"data: {json.dumps({'status': 'Cloning repository and running security scans...'})}\n\n"
            
            scan_response = requests.post(f"{CODE_URL}/scan", json=payload)
            if not scan_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'Code agent scan failed: HTTP {scan_response.status_code}'})}\n\n"
                return
            
            scan_results = scan_response.json()
            
            # Wait for confirmation that all scanning is complete
            if scan_results.get('message') != 'ok':
                yield f"event: error\ndata: {json.dumps({'error': 'Security scan did not complete successfully'})}\n\n"
                return
                
            yield f"data: {json.dumps({'status': 'Security scan completed, starting AI analysis...'})}\n\n"
            
            # Step 2: Send scan results to LLM for streaming analysis
            llm_response = requests.post(
                f"{LLM_URL.rstrip('/')}/analyze/stream", 
                json=scan_results, 
                stream=True
            )
            
            if not llm_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'LLM service error: HTTP {llm_response.status_code}'})}\n\n"
                return
            
            # Step 3: Proxy the streaming response from LLM
            buffer = ''
            for chunk in llm_response.iter_content(chunk_size=1024, decode_unicode=True):
                if not chunk:
                    continue
                    
                buffer += chunk
                
                # Process complete SSE events
                while '\n\n' in buffer:
                    event_end = buffer.find('\n\n')
                    event_data = buffer[:event_end].strip()
                    buffer = buffer[event_end + 2:]
                    
                    if not event_data or event_data.startswith(':'):
                        continue
                    
                    # Forward the event as-is
                    yield f"{event_data}\n\n"
                    
                    # Add heartbeat periodically
                    if time.time() - last_beat > 10:
                        yield ": keep-alive\n\n"
                        last_beat = time.time()
                        
        except requests.exceptions.RequestException as e:
            yield f"event: error\ndata: {json.dumps({'error': f'Request failed: {str(e)}'})}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

@app.post("/scan/container/stream")
def scan_container_stream():
    payload = request.get_json(silent=True) or {}
    
    def event_stream():
        yield "event: start\ndata: {}\n\n"
        last_beat = time.time()
        
        try:
            # Step 1: Call container agent to perform actual security scan
            yield f"data: {json.dumps({'status': 'Cloning repository and running container security scans...'})}\n\n"
            
            scan_response = requests.post(f"{CONT_URL}/scan", json=payload)
            if not scan_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'Container agent scan failed: HTTP {scan_response.status_code}'})}\n\n"
                return
            
            scan_results = scan_response.json()
            
            # Wait for confirmation that all scanning is complete
            if scan_results.get('message') != 'ok':
                yield f"event: error\ndata: {json.dumps({'error': 'Container security scan did not complete successfully'})}\n\n"
                return
                
            yield f"data: {json.dumps({'status': 'Container security scan completed, starting AI analysis...'})}\n\n"
            
            # Step 2: Send scan results to LLM for streaming analysis
            llm_response = requests.post(
                f"{LLM_URL.rstrip('/')}/analyze/stream", 
                json=scan_results, 
                stream=True
            )
            
            if not llm_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'LLM service error: HTTP {llm_response.status_code}'})}\n\n"
                return
            
            # Step 3: Proxy the streaming response from LLM
            buffer = ''
            for chunk in llm_response.iter_content(chunk_size=1024, decode_unicode=True):
                if not chunk:
                    continue
                    
                buffer += chunk
                
                # Process complete SSE events
                while '\n\n' in buffer:
                    event_end = buffer.find('\n\n')
                    event_data = buffer[:event_end].strip()
                    buffer = buffer[event_end + 2:]
                    
                    if not event_data or event_data.startswith(':'):
                        continue
                    
                    # Forward the event as-is
                    yield f"{event_data}\n\n"
                    
                    # Add heartbeat periodically
                    if time.time() - last_beat > 10:
                        yield ": keep-alive\n\n"
                        last_beat = time.time()
                        
        except requests.exceptions.RequestException as e:
            yield f"event: error\ndata: {json.dumps({'error': f'Request failed: {str(e)}'})}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

@app.post("/scan/k8s/stream")
def scan_k8s_stream():
    payload = request.get_json(silent=True) or {}
    
    def event_stream():
        yield "event: start\ndata: {}\n\n"
        last_beat = time.time()
        
        try:
            # Step 1: Call k8s agent to perform actual security scan
            yield f"data: {json.dumps({'status': 'Cloning repository and running K8s security analysis...'})}\n\n"
            
            scan_response = requests.post(f"{K8S_URL}/scan", json=payload)
            if not scan_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'K8s agent scan failed: HTTP {scan_response.status_code}'})}\n\n"
                return
            
            scan_results = scan_response.json()
            
            # Wait for confirmation that all scanning is complete
            if scan_results.get('message') != 'ok':
                yield f"event: error\ndata: {json.dumps({'error': 'K8s security analysis did not complete successfully'})}\n\n"
                return
                
            yield f"data: {json.dumps({'status': 'K8s security analysis completed, starting AI analysis...'})}\n\n"
            
            # Step 2: Send scan results to LLM for streaming analysis
            llm_response = requests.post(
                f"{LLM_URL.rstrip('/')}/analyze/stream", 
                json=scan_results, 
                stream=True
            )
            
            if not llm_response.ok:
                yield f"event: error\ndata: {json.dumps({'error': f'LLM service error: HTTP {llm_response.status_code}'})}\n\n"
                return
            
            # Step 3: Proxy the streaming response from LLM
            buffer = ''
            for chunk in llm_response.iter_content(chunk_size=1024, decode_unicode=True):
                if not chunk:
                    continue
                    
                buffer += chunk
                
                # Process complete SSE events
                while '\n\n' in buffer:
                    event_end = buffer.find('\n\n')
                    event_data = buffer[:event_end].strip()
                    buffer = buffer[event_end + 2:]
                    
                    if not event_data or event_data.startswith(':'):
                        continue
                    
                    # Forward the event as-is
                    yield f"{event_data}\n\n"
                    
                    # Add heartbeat periodically
                    if time.time() - last_beat > 10:
                        yield ": keep-alive\n\n"
                        last_beat = time.time()
                        
        except requests.exceptions.RequestException as e:
            yield f"event: error\ndata: {json.dumps({'error': f'Request failed: {str(e)}'})}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

@app.get("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5080) 