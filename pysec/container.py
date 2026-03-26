"""
Container Scanning - Scan Docker images for CVEs
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

RATE_LIMITS = {}
DEFERRED_TESTS = []


def run_command(cmd: list, rate_key: str = "default") -> tuple[int, str]:
    global RATE_LIMITS, DEFERRED_TESTS
    
    now = time.time()
    last_call = RATE_LIMITS.get(rate_key, 0)
    if now - last_call < 2:
        return 0, "Rate limited - deferred"
    RATE_LIMITS[rate_key] = now
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode, result.stdout + result.stderr
    except Exception as e:
        if "rate" in str(e).lower() or "tpm" in str(e).lower():
            if rate_key not in DEFERRED_TESTS:
                DEFERRED_TESTS.append(rate_key)
        return 1, str(e)


def check_docker() -> bool:
    """Check if Docker is available"""
    code, _ = run_command(["docker", "--version"])
    return code == 0


def check_trivy() -> bool:
    """Check if Trivy is available"""
    code, _ = run_command(["which", "trivy"])
    return code == 0


def check_anchore() -> bool:
    """Check if Anchore is available"""
    code, _ = run_command(["which", "anchore-cli"])
    return code == 0


def scan_dockerfile(dockerfile: str = "Dockerfile") -> list[dict]:
    """Scan Dockerfile for security issues"""
    if not Path(dockerfile).exists():
        return [{"error": f"Dockerfile not found: {dockerfile}"}]
    
    content = Path(dockerfile).read_text()
    results = []
    
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        line_lower = line.lower().strip()
        
        if line_lower.startswith("from") and ":latest" in line_lower:
            results.append({
                "type": "dockerfile",
                "severity": "medium",
                "description": "Avoid using :latest tag, pin specific version",
                "location": f"{dockerfile}:{i}"
            })
        
        if "root" in line_lower and "user" not in line_lower:
            results.append({
                "type": "dockerfile",
                "severity": "medium",
                "description": "Consider running as non-root user",
                "location": f"{dockerfile}:{i}"
            })
        
        if line_lower.startswith("add ") or line_lower.startswith("copy ") and "http" in line_lower:
            results.append({
                "type": "dockerfile",
                "severity": "high",
                "description": "Avoid adding files from URLs, use curl/wget in build step",
                "location": f"{dockerfile}:{i}"
            })
        
        if "expose" in line_lower and not line_lower.startswith("#"):
            port = line_lower.replace("expose", "").strip()
            if port and port.isdigit():
                results.append({
                    "type": "dockerfile",
                    "severity": "low",
                    "description": f"Port {port} exposed - ensure it's necessary",
                    "location": f"{dockerfile}:{i}"
                })
    
    return results


def scan_with_trivy(image: str = "docker-image:latest") -> list[dict]:
    """Scan Docker image with Trivy"""
    if not check_trivy():
        return [{"error": "Trivy not installed. Install: https://aquasecurity.github.io/trivy/"}]
    
    code, output = run_command(["trivy", "image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", image])
    
    try:
        data = json.loads(output) if output else {}
        results = []
        
        for vuln in data.get("Results", []):
            for target in vuln.get("Vulnerabilities", []):
                results.append({
                    "type": "container",
                    "severity": target.get("Severity", "unknown"),
                    "description": target.get("Description", target.get("Title", "")),
                    "location": f"{image}:{target.get('PkgName', 'unknown')}",
                    "cve_id": target.get("ID", ""),
                    "tool": "trivy"
                })
        return results
    except:
        return [{"error": "Failed to scan with Trivy", "output": output[:500]}]


def scan_with_anchore(image: str = "docker-image:latest") -> list[dict]:
    """Scan Docker image with Anchore"""
    if not check_anchore():
        return [{"error": "Anchore CLI not installed"}]
    
    code, output = run_command(["anchore-cli", "image", "vuln", image, "all"])
    
    if code != 0:
        return [{"error": f"Anchore scan failed: {output}"}]
    
    results = []
    for line in output.split("\n"):
        if "HIGH" in line or "CRITICAL" in line:
            results.append({
                "type": "container",
                "severity": "high" if "CRITICAL" in line else "medium",
                "description": line.strip(),
                "location": image,
                "tool": "anchore"
            })
    
    return results


def scan_container(image: str = None, dockerfile: str = "Dockerfile") -> list[dict]:
    """Scan container - Dockerfile and/or image"""
    results = []
    
    results.extend(scan_dockerfile(dockerfile))
    
    if image and check_trivy():
        results.extend(scan_with_trivy(image))
    elif image and check_anchore():
        results.extend(scan_with_anchore(image))
    elif image and not check_trivy() and not check_anchore():
        results.append({
            "type": "container",
            "severity": "info",
            "description": "No container scanner installed. Install Trivy for image scanning.",
            "location": "system"
        })
    
    return results