#!/usr/bin/env python3
"""
README Agent - Watches build outputs and updates README with metadata
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


def run_command(cmd: str) -> Optional[str]:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def get_git_info() -> dict:
    branch = run_command("git rev-parse --abbrev-ref HEAD") or ""
    commit = (run_command("git rev-parse --short HEAD") or "")[:7]
    date = run_command("git log -1 --format=%cd --date=short") or ""
    return {"branch": branch, "commit": commit, "date": date}


def get_project_metadata() -> dict:
    meta = {"python_version": None, "dependencies": [], "package_name": None}

    if Path("pyproject.toml").exists():
        content = Path("pyproject.toml").read_text()
        if match := re.search(r'name\s*=\s*"([^"]+)"', content):
            meta["package_name"] = match.group(1)
        if match := re.search(r'python\s*=\s*"([^"]+)"', content):
            meta["python_version"] = match.group(1)
        deps = re.findall(r'^([^=\s]+)', content, re.MULTILINE)
        meta["dependencies"] = [d for d in deps if d in ["pytest", "ruff", "mypy", "black", "coverage"]]

    elif Path("setup.py").exists():
        content = Path("setup.py").read_text()
        if match := re.search(r'name\s*=\s*"([^"]+)"', content):
            meta["package_name"] = match.group(1)

    elif Path("package.json").exists():
        content = Path("package.json").read_text()
        try:
            data = json.loads(content)
            meta["package_name"] = data.get("name")
            meta["dependencies"] = list(data.get("dependencies", {}).keys())[:5]
        except:
            pass

    return meta


def get_ci_status() -> dict:
    status = {"github_actions": False, "last_build": None, "tests": None}
    
    if Path(".github/workflows").exists():
        status["github_actions"] = True
    
    if coverage := run_command("cat coverage/coverage.json 2>/dev/null || echo"):
        try:
            data = json.loads(coverage)
            status["coverage"] = f"{data.get('totals', {}).get('percent_covered', 0):.1f}%"
        except:
            pass
    
    if pytest := run_command("cat .pytest-results.json 2>/dev/null || echo"):
        try:
            data = json.loads(pytest)
            passed = data.get("summary", {}).get("passed", 0)
            failed = data.get("summary", {}).get("failed", 0)
            status["tests"] = f"{passed} passed, {failed} failed"
        except:
            pass
    
    return status


def get_activity_stats() -> dict:
    stats: dict = {"contributors": [], "last_commit": None}
    
    if contributors := run_command("git shortlog -sn --no-merges | head -5"):
        lines = contributors.strip().split("\n")
        stats["contributors"] = [line.split("\t")[1] if "\t" in line else line for line in lines[:3]]
    
    return stats


def generate_readme_section(git_info: dict, metadata: dict, ci_status: dict, activity: dict) -> str:
    lines = ["<!-- README-AGENT:START -->"]
    lines.append(f"### Project Information")
    lines.append("")
    lines.append(f"| Property | Value |")
    lines.append(f"|----------|-------|")
    
    if metadata.get("package_name"):
        lines.append(f"| Package | `{metadata['package_name']}` |")
    if metadata.get("python_version"):
        lines.append(f"| Python | {metadata['python_version']} |")
    if git_info.get("branch"):
        lines.append(f"| Branch | `{git_info['branch']}` |")
    if git_info.get("commit"):
        lines.append(f"| Commit | `{git_info['commit']}` |")
    if git_info.get("date"):
        lines.append(f"| Last Updated | {git_info['date']} |")
    
    lines.append("")
    lines.append("### Dependencies")
    lines.append("")
    if metadata.get("dependencies"):
        deps = ", ".join(f"`{d}`" for d in metadata["dependencies"])
        lines.append(f"_{deps}_")
    else:
        lines.append("_None detected_")
    
    lines.append("")
    lines.append("### CI/CD Status")
    lines.append("")
    lines.append(f"| Status | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| GitHub Actions | {'✅ Enabled' if ci_status.get('github_actions') else '❌ Not configured'} |")
    if ci_status.get("coverage"):
        lines.append(f"| Coverage | {ci_status['coverage']} |")
    if ci_status.get("tests"):
        lines.append(f"| Tests | {ci_status['tests']} |")
    
    if activity.get("contributors"):
        lines.append("")
        lines.append("### Top Contributors")
        lines.append("")
        for c in activity["contributors"]:
            lines.append(f"- {c}")
    
    lines.append("")
    lines.append(f"_Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_")
    lines.append("<!-- README-AGENT:END -->")
    return "\n".join(lines)


def update_readme(readme_path: Path, section: str):
    content = readme_path.read_text()
    
    pattern = r"<!-- README-AGENT:START -->.*?<!-- README-AGENT:END -->"
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, section, content, flags=re.DOTALL)
    else:
        content = content.rstrip() + "\n\n" + section
    
    readme_path.write_text(content)
    print(f"Updated {readme_path}")


def watch_builds(interval: int = 30):
    print(f"Watching for build outputs... (checking every {interval}s)")
    print("Press Ctrl+C to stop")
    
    markers = [".pytest-results.json", "coverage/coverage.json", "build/latest"]
    last_checked = {}
    
    try:
        while True:
            for marker in markers:
                if Path(marker).exists():
                    mtime = Path(marker).stat().st_mtime
                    if marker not in last_checked or mtime > last_checked[marker]:
                        last_checked[marker] = mtime
                        print(f"Change detected: {marker}")
                        run(readme_path="README.md")
            
            import time
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching")


def run(readme_path: str = "README.md"):
    git_info = get_git_info()
    metadata = get_project_metadata()
    ci_status = get_ci_status()
    activity = get_activity_stats()
    
    section = generate_readme_section(git_info, metadata, ci_status, activity)
    update_readme(Path(readme_path), section)
    
    print(f"Branch: {git_info.get('branch')} | Commit: {git_info.get('commit')}")
    print(f"Python: {metadata.get('python_version')} | Package: {metadata.get('package_name')}")


def main():
    parser = argparse.ArgumentParser(description="README Agent - Updates README with build info")
    parser.add_argument("--readme", default="README.md", help="Path to README file")
    parser.add_argument("--watch", action="store_true", help="Watch for build changes")
    parser.add_argument("--interval", type=int, default=30, help="Watch interval in seconds")
    args = parser.parse_args()
    
    if args.watch:
        watch_builds(args.interval)
    else:
        run(args.readme)


if __name__ == "__main__":
    main()