"""
SAST Integration - Static Application Security Testing using Bandit, Semgrep, Ruff
"""

import json
import subprocess
from pathlib import Path
from typing import Optional


def run_command(cmd: list) -> tuple[int, str]:
    """Run command and return (exit_code, output)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode, result.stdout + result.stderr
    except Exception as e:
        return 1, str(e)


def check_bandit() -> bool:
    """Check if Bandit is available"""
    code, _ = run_command(["which", "bandit"])
    return code == 0


def check_semgrep() -> bool:
    """Check if Semgrep is available"""
    code, _ = run_command(["which", "semgrep"])
    return code == 0


def check_ruff() -> bool:
    """Check if Ruff is available"""
    code, _ = run_command(["which", "ruff"])
    return code == 0


def scan_with_bandit(path: str = ".") -> list[dict]:
    """Scan with Bandit"""
    if not check_bandit():
        return [{"error": "Bandit not installed. Install with: pip install bandit"}]
    
    code, output = run_command(["bandit", "-r", "-f", "json", path])
    
    try:
        data = json.loads(output) if output else {"results": []}
        results = []
        
        for issue in data.get("results", []):
            results.append({
                "type": "sast-bandit",
                "severity": issue.get("issue_severity", "medium"),
                "description": issue.get("issue_text", ""),
                "location": f"{issue.get('filename')}:{issue.get('line_number')}",
                "rule": issue.get("issue_cwe", {}).get("link", ""),
                "tool": "bandit"
            })
        return results
    except:
        return [{"error": "Failed to parse Bandit output", "output": output[:500]}]


def scan_with_semgrep(path: str = ".") -> list[dict]:
    """Scan with Semgrep"""
    if not check_semgrep():
        return [{"error": "Semgrep not installed. Install from: https://semgrep.dev/docs/getting-started/"}]
    
    code, output = run_command(["semgrep", "--json", "--quiet", path])
    
    try:
        data = json.loads(output) if output else {"results": []}
        results = []
        
        for issue in data.get("results", []):
            results.append({
                "type": "sast-semgrep",
                "severity": issue.get("extra", {}).get("severity", "medium"),
                "description": issue.get("extra", {}).get("message", ""),
                "location": f"{issue.get('path')}:{issue.get('start', {}).get('line', 0)}",
                "rule": issue.get("check_id", ""),
                "tool": "semgrep"
            })
        return results
    except:
        return [{"error": "Failed to parse Semgrep output", "output": output[:500]}]


def scan_with_ruff(path: str = ".") -> list[dict]:
    """Scan with Ruff (security rules)"""
    if not check_ruff():
        return [{"error": "Ruff not installed. Install with: pip install ruff"}]
    
    code, output = run_command(["ruff", "check", "--select=SEC", "--output-format=json", path])
    
    try:
        data = json.loads(output) if output and output.strip().startswith("[") else []
        results = []
        
        for issue in data:
            severity = issue.get("severity", "MEDIUM")
            severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            results.append({
                "type": "sast-ruff",
                "severity": severity_map.get(severity, "medium"),
                "description": issue.get("message", ""),
                "location": f"{issue.get('filename')}:{issue.get('location', {}).get('row', 0)}",
                "rule": issue.get("code", ""),
                "tool": "ruff"
            })
        return results
    except:
        return []


def scan_all_sast(path: str = ".") -> list[dict]:
    """Run all available SAST tools"""
    results = []
    
    if check_bandit():
        results.extend(scan_with_bandit(path))
    
    if check_semgrep():
        results.extend(scan_with_semgrep(path))
    
    if check_ruff():
        results.extend(scan_with_ruff(path))
    
    if not any([check_bandit(), check_semgrep(), check_ruff()]):
        return [{
            "type": "sast",
            "severity": "info",
            "description": "No SAST tools installed. Install Bandit, Semgrep, or Ruff for enhanced security scanning.",
            "location": "system",
            "install": "pip install bandit semgrep ruff"
        }]
    
    return results