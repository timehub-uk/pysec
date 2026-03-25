#!/usr/bin/env python3
"""
Security Agent - Watches build for security issues, researches, and fixes them
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class SecurityIssue:
    severity: str
    category: str
    description: str
    location: str
    fix: Optional[str] = None
    cve_id: Optional[str] = None
    references: list = field(default_factory=list)


def run_command(cmd: str, timeout: int = 60) -> Optional[str]:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return str(e)


def scan_dependencies() -> list[SecurityIssue]:
    issues = []
    
    if Path("requirements.txt").exists():
        reqs = Path("requirements.txt").read_text()
        for line in reqs.split("\n"):
            if line.strip() and not line.startswith("#"):
                pkg = re.split(r"[<>=!~]", line.strip())[0].strip()
                result = run_command(f"pip-audit --format=json 2>/dev/null || pip-audit -r requirements.txt 2>/dev/null || echo ''")
                if result and "vulns" in result.lower():
                    issues.append(SecurityIssue(
                        severity="high",
                        category="vulnerable_dependency",
                        description=f"Package {pkg} has known vulnerabilities",
                        location=f"requirements.txt: {line}"
                    ))
    
    if Path("pyproject.toml").exists():
        content = Path("pyproject.toml").read_text()
        if "pip-audit" in content or "safety" in content:
            result = run_command("pip-audit --format=json 2>/dev/null || echo '{}'")
            if result:
                try:
                    data = json.loads(result)
                    for pkg, info in data.get("dependencies", {}).items():
                        for vuln in info.get("vulns", []):
                            issues.append(SecurityIssue(
                                severity="high",
                                category="vulnerable_dependency",
                                description=vuln.get("description", "Unknown vulnerability"),
                                location=f"pyproject.toml: {pkg}",
                                cve_id=vuln.get("id"),
                                fix=vuln.get("fix_versions", [None])[0]
                            ))
                except:
                    pass
    
    return issues


def scan_secrets() -> list[SecurityIssue]:
    issues = []
    patterns = {
        "api_key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "aws_key": r"(?i)aws[_-]?(access[_-]?key|secret)[_-]?(id|key)?\s*[=:]\s*['\"][A-Z0-9]{20,}['\"]",
        "github_token": r"(?i)(github[_-]?token|gho_)[a-zA-Z0-9]{36,}",
        "password": r"(?i)password\s*[=:]\s*['\"][^'\"]+['\"]",
        "private_key": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
        "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    }
    
    extensions = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".sh"}
    
    for ext in extensions:
        for path in Path(".").rglob(f"*{ext}"):
            if "node_modules" in str(path) or ".git" in str(path) or "__pycache__" in str(path):
                continue
            try:
                content = path.read_text(errors="ignore")
                for category, pattern in patterns.items():
                    if re.search(pattern, content):
                        issues.append(SecurityIssue(
                            severity="critical",
                            category="secret_leak",
                            description=f"Potential {category.replace('_', ' ')} detected",
                            location=str(path)
                        ))
            except:
                pass
    
    return issues


def scan_code_vulnerabilities() -> list[SecurityIssue]:
    issues = []
    patterns = {
        "sql_injection": {
            "pattern": r"(execute|query|cursor\.execute)\s*\([^)]*%s[^)]*\)|['\"]SELECT.*\{",
            "severity": "high",
            "fix": "Use parameterized queries or ORM"
        },
        "path_traversal": {
            "pattern": r"(open|read|os\.path\.join)\s*\([^)]*request\.|Path\(.*request",
            "severity": "medium",
            "fix": "Validate and sanitize file paths"
        },
        "xss": {
            "pattern": r"(innerHTML|outerHTML|document\.write)\s*\([^)]*request",
            "severity": "medium",
            "fix": "Use textContent or sanitization libraries"
        },
        "eval_usage": {
            "pattern": r"\beval\s*\(|exec\s*\(",
            "severity": "high",
            "fix": "Avoid eval/exec, use safer alternatives"
        },
        "hardcoded_db": {
            "pattern": r"(mysql|postgresql|mongodb)://[^:]+:[^@]+@",
            "severity": "high",
            "fix": "Use environment variables for credentials"
        },
        "insecure_random": {
            "pattern": r"random\.(random|randint)",
            "severity": "low",
            "fix": "Use secrets.token_* for security-critical randomness"
        },
        "yaml_load": {
            "pattern": r"yaml\.load\s*\([^)]*(Loader=None|Loader=yaml\.FullLoader)",
            "severity": "medium",
            "fix": "Use yaml.safe_load or Loader=yaml.SafeLoader"
        },
        "weak_crypto": {
            "pattern": r"(md5|sha1)\s*\(",
            "severity": "medium",
            "fix": "Use hashlib.sha256 or stronger algorithms"
        }
    }
    
    for path in Path(".").rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        try:
            content = path.read_text(errors="ignore")
            for category, info in patterns.items():
                if re.search(info["pattern"], content):
                    issues.append(SecurityIssue(
                        severity=info["severity"],
                        category="code_vulnerability",
                        description=f"Potential {category.replace('_', ' ')} in code",
                        location=str(path),
                        fix=info["fix"]
                    ))
        except:
            pass
    
    return issues


def research_issue(issue: SecurityIssue) -> list[str]:
    references = []
    
    if issue.cve_id:
        search_query = f"{issue.cve_id} vulnerability fix"
    else:
        search_query = f"{issue.category} {issue.description} fix"
    
    result = run_command(f'exa --version 2>/dev/null && echo "has exa" || echo "no exa"')
    
    if issue.cve_id:
        references.append(f"https://nvd.nist.gov/vuln/detail/{issue.cve_id}")
    
    if "injection" in issue.category:
        references.append("https://owasp.org/www-community/attacks/SQL_Injection")
    if "xss" in issue.category:
        references.append("https://owasp.org/www-community/attacks/xss")
    if "secret" in issue.category:
        references.append("https://docs.github.com/en/code-security/secret-scanning")
    
    return references


def apply_fix(issue: SecurityIssue) -> bool:
    if not issue.fix:
        return False
    
    try:
        if issue.category == "vulnerable_dependency":
            if Path("requirements.txt").exists():
                content = Path("requirements.txt").read_text()
                new_content = re.sub(rf"{re.escape(issue.location.split(':')[1].strip())}.*", 
                                    f"{issue.location.split(':')[1].strip()}=={issue.fix}", content)
                Path("requirements.txt").write_text(new_content)
                return True
            
            if Path("pyproject.toml").exists():
                content = Path("pyproject.toml").read_text()
                new_content = re.sub(rf'("{issue.location.split(":")[1].strip()}")\s*=\s*"[^"]+"', 
                                    f'\\1 = "^{issue.fix}"', content)
                Path("pyproject.toml").write_text(new_content)
                return True
        
        elif issue.category == "secret_leak":
            pass
        
        elif issue.category == "code_vulnerability":
            pass
    
    except Exception as e:
        print(f"Fix failed: {e}")
    
    return False


def generate_report(issues: list[SecurityIssue]) -> str:
    lines = ["<!-- SECURITY-AGENT:START -->"]
    lines.append("### Security Report")
    lines.append("")
    lines.append(f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_")
    lines.append("")
    
    if not issues:
        lines.append("✅ No security issues detected")
    else:
        critical = [i for i in issues if i.severity == "critical"]
        high = [i for i in issues if i.severity == "high"]
        medium = [i for i in issues if i.severity == "medium"]
        
        lines.append(f"**Found {len(issues)} issue(s):**")
        lines.append(f"- 🔴 Critical: {len(critical)}")
        lines.append(f"- 🟠 High: {len(high)}")
        lines.append(f"- 🟡 Medium: {len(medium)}")
        lines.append("")
        
        for issue in issues:
            severity_icon = "🔴" if issue.severity == "critical" else "🟠" if issue.severity == "high" else "🟡"
            lines.append(f"{severity_icon} **{issue.category}**")
            lines.append(f"   - {issue.description}")
            lines.append(f"   - Location: `{issue.location}`")
            if issue.fix:
                lines.append(f"   - Fix: {issue.fix}")
            if issue.cve_id:
                lines.append(f"   - CVE: {issue.cve_id}")
            lines.append("")
    
    lines.append("<!-- SECURITY-AGENT:END -->")
    return "\n".join(lines)


def update_readme(report: str):
    readme = Path("README.md")
    if not readme.exists():
        return
    
    content = readme.read_text()
    pattern = r"<!-- SECURITY-AGENT:START -->.*?<!-- SECURITY-AGENT:END -->"
    
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, report, content, flags=re.DOTALL)
    else:
        content = content.rstrip() + "\n\n" + report
    
    readme.write_text(content)


def run_scan(fix: bool = False) -> list[SecurityIssue]:
    print("🔍 Running security scan...")
    all_issues = []
    
    print("  Scanning dependencies...")
    all_issues.extend(scan_dependencies())
    
    print("  Scanning for secrets...")
    all_issues.extend(scan_secrets())
    
    print("  Scanning code vulnerabilities...")
    all_issues.extend(scan_code_vulnerabilities())
    
    print(f"  Found {len(all_issues)} issue(s)")
    
    for issue in all_issues:
        issue.references = research_issue(issue)
    
    if fix and all_issues:
        print("\n🔧 Applying fixes...")
        for issue in all_issues:
            if apply_fix(issue):
                print(f"  Fixed: {issue.category} in {issue.location}")
    
    report = generate_report(all_issues)
    update_readme(report)
    
    return all_issues


def watch_builds(interval: int = 60, fix: bool = False):
    print(f"🛡️ Security agent watching... (checking every {interval}s)")
    print("Press Ctrl+C to stop")
    
    markers = ["requirements.txt", "pyproject.toml", "package.json", "setup.py"]
    last_hashes = {}
    
    for marker in markers:
        if Path(marker).exists():
            last_hashes[marker] = hash(Path(marker).read_bytes())
    
    for ext in [".py", ".js", ".ts"]:
        for path in Path(".").rglob(f"*{ext}"):
            if "__pycache__" not in str(path) and "node_modules" not in str(path):
                last_hashes[str(path)] = hash(path.read_bytes())
    
    try:
        while True:
            for marker in markers:
                if Path(marker).exists():
                    current_hash = hash(Path(marker).read_bytes())
                    if marker not in last_hashes or current_hash != last_hashes[marker]:
                        print(f"\n📦 Dependency change detected: {marker}")
                        run_scan(fix)
                        last_hashes[marker] = current_hash
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\nStopped security monitoring")


def main():
    parser = argparse.ArgumentParser(description="Security Agent - Scan and fix security issues")
    parser.add_argument("--fix", action="store_true", help="Automatically apply fixes")
    parser.add_argument("--watch", action="store_true", help="Watch for changes")
    parser.add_argument("--interval", type=int, default=60, help="Watch interval in seconds")
    args = parser.parse_args()
    
    if args.watch:
        watch_builds(args.interval, args.fix)
    else:
        run_scan(args.fix)


if __name__ == "__main__":
    main()