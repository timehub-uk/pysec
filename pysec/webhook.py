#!/usr/bin/env python3
"""
Webhook handler for pysec - receives scan results from CI/CD
"""

import json
import hmac
import hashlib
from pathlib import Path
from flask import Flask, request, jsonify
from datetime import datetime


app = Flask(__name__)

WEBHOOK_SECRET = None  # Set via WEBHOOK_SECRET env var
RESULTS_DIR = Path("scan-results")


def verify_signature(payload):
    if not WEBHOOK_SECRET:
        return True  # Skip verification if no secret set
    
    signature = request.headers.get("X-Signature")
    if not signature:
        return False
    
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected}", signature)


@app.route("/webhook", methods=["POST"])
def handle_webhook():
    if not verify_signature(request.data):
        return jsonify({"error": "Invalid signature"}), 401
    
    data = request.json
    
    if data.get("event") == "scan_completed":
        results = data.get("results", {})
        repo = data.get("repository", "unknown")
        branch = data.get("branch", "unknown")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = RESULTS_DIR / f"{repo}_{branch}_{timestamp}.json"
        
        RESULTS_DIR.mkdir(exist_ok=True)
        filename.write_text(json.dumps(results, indent=2))
        
        summary = results.get("summary", {})
        
        return jsonify({
            "status": "stored",
            "file": str(filename),
            "summary": summary,
            "message": f"Found {summary.get('total', 0)} issues"
        })
    
    return jsonify({"error": "Unknown event"}), 400


@app.route("/results", methods=["GET"])
def list_results():
    if not RESULTS_DIR.exists():
        return jsonify({"results": []})
    
    results = []
    for f in RESULTS_DIR.glob("*.json"):
        data = json.loads(f.read_text())
        results.append({
            "file": f.name,
            "summary": data.get("summary", {}),
            "timestamp": f.stat().st_mtime
        })
    
    return jsonify({"results": sorted(results, key=lambda x: x["timestamp"], reverse=True)})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


if __name__ == "__main__":
    import os
    WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")
    app.run(host="0.0.0.0", port=8080)