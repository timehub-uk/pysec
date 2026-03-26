import json
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


def generate_json_report(results, output_file=None):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    sorted_results = sorted(
        results,
        key=lambda x: (severity_order.get(x.get("severity", "low"), 3), x.get("location", ""))
    )
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "critical": len([r for r in results if r.get("severity") == "critical"]),
            "high": len([r for r in results if r.get("severity") == "high"]),
            "medium": len([r for r in results if r.get("severity") == "medium"]),
            "low": len([r for r in results if r.get("severity") == "low"]),
        },
        "issues": sorted_results
    }
    
    json_output = json.dumps(report, indent=2)
    
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        console.print(f"[green]Report saved to {output_file}[/green]")
    
    return json_output


def generate_html_report(results, output_file=None):
    severity_colors = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#00cc00"
    }
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_results = sorted(
        results,
        key=lambda x: (severity_order.get(x.get("severity", "low"), 3), x.get("location", ""))
    )
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 5px; flex: 1; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ color: #ff0000; font-size: 24px; font-weight: bold; }}
        .high {{ color: #ff6600; font-size: 24px; font-weight: bold; }}
        .medium {{ color: #ffcc00; font-size: 24px; font-weight: bold; }}
        .low {{ color: #00cc00; font-size: 24px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f9f9f9; }}
        .severity {{ padding: 4px 8px; border-radius: 3px; color: white; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <div class="critical">{len([r for r in results if r.get('severity') == 'critical'])}</div>
            <div>Critical</div>
        </div>
        <div class="summary-card">
            <div class="high">{len([r for r in results if r.get('severity') == 'high'])}</div>
            <div>High</div>
        </div>
        <div class="summary-card">
            <div class="medium">{len([r for r in results if r.get('severity') == 'medium'])}</div>
            <div>Medium</div>
        </div>
        <div class="summary-card">
            <div class="low">{len([r for r in results if r.get('severity') == 'low'])}</div>
            <div>Low</div>
        </div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Description</th>
                <th>Location</th>
            </tr>
        </thead>
        <tbody>
"""
    
    for r in sorted_results:
        severity = r.get("severity", "low")
        color = severity_colors.get(severity, "#00cc00")
        html += f"""            <tr>
                <td><span class="severity" style="background: {color}">{severity.upper()}</span></td>
                <td>{r.get('type', 'unknown')}</td>
                <td>{r.get('description', '')}</td>
                <td><code>{r.get('location', '')}</code></td>
            </tr>
"""
    
    html += """        </tbody>
    </table>
</body>
</html>"""
    
    if output_file:
        with open(output_file, "w") as f:
            f.write(html)
        console.print(f"[green]Report saved to {output_file}[/green]")
    
    return html


def display_results(results):
    if not results:
        console.print(Panel.fit("[bold green]✓ No security issues found[/bold green]"))
        return
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_results = sorted(
        results,
        key=lambda x: (severity_order.get(x.get("severity", "low"), 3), x.get("location", ""))
    )
    
    table = Table(title="🔒 Security Issues Found")
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Description")
    table.add_column("Location")
    
    for r in sorted_results:
        severity = r.get("severity", "unknown")
        style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green"
        }.get(severity, "")
        
        table.add_row(
            severity.upper(),
            r.get("type", "unknown"),
            r.get("description", "")[:60],
            r.get("location", "")
        )
    
    console.print(table)
    
    critical = len([r for r in results if r.get("severity") == "critical"])
    high = len([r for r in results if r.get("severity") == "high"])
    medium = len([r for r in results if r.get("severity") == "medium"])
    low = len([r for r in results if r.get("severity") == "low"])
    
    # Check for deferred tests
    try:
        from pysec.deps import DEFERRED_TESTS
        if DEFERRED_TESTS:
            console.print(f"\n[bold yellow]⚠ Deferred {len(DEFERRED_TESTS)} tests due to rate limiting[/bold yellow]")
            console.print(f"  Deferred: {', '.join(DEFERRED_TESTS[:5])}")
    except:
        pass
    
    console.print(f"\nTotal: {len(results)} issue(s) | Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")


def display_table(results):
    display_results(results)