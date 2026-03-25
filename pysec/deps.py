import subprocess
import json
import re
from pathlib import Path


def scan_dependencies(path):
    results = []
    
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
            result = subprocess.run(
                ["pip", "index", "versions", pkg],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                results.append({
                    "type": "vulnerable_dependency",
                    "severity": "medium",
                    "description": f"Package {pkg} not found in PyPI",
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
    result = subprocess.run(
        ["pip-audit", "--format=json", name],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            vulns = data.get("vulns", [])
            return {"vulns": [v["id"] for v in vulns]}
        except:
            pass
    
    return {"vulns": []}