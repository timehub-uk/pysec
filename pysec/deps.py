import subprocess
import json
import re
import time
from pathlib import Path

RATE_LIMITS = {}
DEFERRED_TESTS = []


def safe_subprocess(cmd, rate_key=None, max_retries=3):
    """Execute subprocess with rate limiting and retry logic"""
    global RATE_LIMITS, DEFERRED_TESTS
    
    now = time.time()
    if rate_key:
        last_call = RATE_LIMITS.get(rate_key, 0)
        if now - last_call < 2:
            if rate_key not in DEFERRED_TESTS:
                DEFERRED_TESTS.append(rate_key)
            return None, "deferred"
        RATE_LIMITS[rate_key] = now
    
    for attempt in range(max_retries):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result, None
        except Exception as e:
            if "rate limit" in str(e).lower() or "tpm" in str(e).lower():
                if rate_key not in DEFERRED_TESTS:
                    DEFERRED_TESTS.append(rate_key)
                return None, "deferred"
            if attempt < max_retries - 1:
                time.sleep(1)
    return None, "failed"


def scan_dependencies(path, ignore_patterns=None):
    results = []
    
    if ignore_patterns is None:
        ignore_patterns = []
    
    if (path / "requirements.txt").exists():
        results.extend(scan_requirements_txt(path / "requirements.txt"))
    
    if (path / "pyproject.toml").exists():
        results.extend(scan_pyproject_toml(path / "pyproject.toml"))
    
    if (path / "setup.py").exists():
        results.extend(scan_setup_py(path / "setup.py"))
    
    return results


def scan_requirements_txt(filepath):
    results = []
    content = filepath.read_text()
    
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        if match := re.match(r"([a-zA-Z0-9_-]+)([=<>!~]+.*)?", line):
            pkg = match.group(1)
            if pkg.strip():
                results.append({
                    "type": "vulnerable_dependency",
                    "severity": "low",
                    "description": f"Dependency: {pkg}",
                    "location": f"{filepath.name}: {line}"
                })
    
    return results


def scan_pyproject_toml(filepath):
    results = []
    content = filepath.read_text()
    
    deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if deps_match:
        deps = re.findall(r'"([^"]+)"', deps_match.group(1))
        for dep in deps:
            pkg = re.split(r"[<>=!~]", dep)[0]
            if pkg.strip():
                results.append({
                    "type": "vulnerable_dependency",
                    "severity": "low",
                    "description": f"Dependency: {pkg}",
                    "location": f"{filepath.name}: {dep}"
                })
    
    return results


def scan_setup_py(filepath):
    results = []
    content = filepath.read_text()
    
    requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if requires_match:
        deps = re.findall(r'"([^"]+)"', requires_match.group(1))
        for dep in deps:
            pkg = re.split(r"[<>=!~]", dep)[0]
            results.append({
                "type": "vulnerable_dependency",
                "severity": "low",
                "description": f"Dependency: {pkg}",
                "location": f"{filepath.name}: {dep}"
            })
    
    return results


def check_package(name):
    return {"vulns": []}