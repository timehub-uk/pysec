from flask import Flask, render_template_string, jsonify
from pathlib import Path
from datetime import datetime
import json


app = Flask(__name__)
RESULTS_DIR = Path("scan-results")


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>pysec Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.8; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .stat-card .number { font-size: 36px; font-weight: bold; }
        .stat-card.critical .number { color: #dc2626; }
        .stat-card.high .number { color: #ea580c; }
        .stat-card.medium .number { color: #ca8a04; }
        .stat-card.low .number { color: #16a34a; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .card { background: white; border-radius: 10px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .card h2 { margin-bottom: 20px; color: #1a1a2e; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { color: #666; font-weight: 600; }
        .severity { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .severity.critical { background: #fef2f2; color: #dc2626; }
        .severity.high { background: #fff7ed; color: #ea580c; }
        .severity.medium { background: #fefce8; color: #ca8a04; }
        .severity.low { background: #f0fdf4; color: #16a34a; }
        .empty { text-align: center; color: #999; padding: 40px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 pysec Security Dashboard</h1>
        <p>Last updated: {{ last_updated }}</p>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat-card critical">
                <div class="number">{{ summary.critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{{ summary.high }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{{ summary.medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{{ summary.low }}</div>
                <div class="label">Low</div>
            </div>
        </div>
        <div class="card">
            <h2>Recent Scans</h2>
            {% if results %}
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                {% for result in results %}
                    <tr>
                        <td>{{ result.file }}</td>
                        <td><span class="severity {{ result.severity }}">{{ result.severity }}</span></td>
                        <td>{{ result.type }}</td>
                        <td>{{ result.description }}</td>
                        <td><code>{{ result.location }}</code></td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty">No scan results yet. Run a scan to see results here.</div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    all_results = []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    last_updated = "Never"
    
    if RESULTS_DIR.exists():
        for f in sorted(RESULTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:1]:
            data = json.loads(f.read_text())
            all_results = data.get("issues", [])[:20]
            summary = data.get("summary", summary)
            last_updated = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    
    return render_template_string(DASHBOARD_TEMPLATE, results=all_results, summary=summary, last_updated=last_updated)


@app.route("/api/results")
def api_results():
    results = []
    if RESULTS_DIR.exists():
        for f in sorted(RESULTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
            data = json.loads(f.read_text())
            results.append({
                "file": f.name,
                "summary": data.get("summary", {}),
                "issues": data.get("issues", [])[:10]
            })
    return jsonify(results)


if __name__ == "__main__":
    RESULTS_DIR.mkdir(exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)