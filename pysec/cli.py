import click
import subprocess
import time
from pathlib import Path
from rich.console import Console
from pysec.scanner import Scanner
from pysec.report import display_results, generate_json_report, generate_html_report

console = Console()


def generate_opencode_instructions(results: list) -> str:
    """Generate fix instructions for OpenCode"""
    by_type = {}
    for issue in results:
        t = issue.get("type", "unknown")
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(issue)
    
    instructions = """## Security Fix Instructions

Fix these security vulnerabilities using best practices:

### SQL Injection
**Good:** `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`

"""
    
    for issue_type, issues in sorted(by_type.items(), key=lambda x: -len(x[1])):
        instructions += f"### {issue_type} ({len(issues)} issues)\n"
        
        if issue_type == "sql_injection":
            instructions += "**Fix:** Use parameterized queries: `cursor.execute(query, (params,))`\n"
        elif issue_type == "hardcoded_secret":
            instructions += "**Fix:** Use `os.environ.get('SECRET')` or `os.getenv('API_KEY')`\n"
        elif issue_type == "eval_usage":
            instructions += "**Fix:** Use `ast.literal_eval()` or `json.loads()` instead of eval/exec\n"
        elif issue_type == "path_traversal":
            instructions += "**Fix:** Use `Path(base) / filename` with validation\n"
        elif issue_type == "yaml_load":
            instructions += "**Fix:** Use `yaml.safe_load()` instead of `yaml.load()`\n"
        elif issue_type == "command_injection":
            instructions += "**Fix:** Use `subprocess.run([args], shell=False)`\n"
        elif issue_type == "weak_crypto":
            instructions += "**Fix:** Use `hashlib.sha256()` instead of MD5/SHA1\n"
        elif issue_type == "insecure_random":
            instructions += "**Fix:** Use `secrets` module instead of `random`\n"
        elif issue_type == "pickle_insecure":
            instructions += "**Fix:** Use `json.loads()` instead of `pickle.loads()`\n"
        elif issue_type == "debug_enabled":
            instructions += "**Fix:** Use `os.environ.get('DEBUG', 'false') == 'true'`\n"
        elif issue_type == "ssl_verify_disabled":
            instructions += "**Fix:** Use `verify=True` instead of `verify=False`\n"
        elif issue_type == "vulnerable_dependency":
            instructions += "**Fix:** Update to latest secure version: `pip install --upgrade PACKAGE`\n"
        
        # Show locations
        for issue in issues[:3]:
            instructions += f"- {issue.get('location', 'unknown')}\n"
        if len(issues) > 3:
            instructions += f"- ... and {len(issues) - 3} more\n"
        instructions += "\n"
    
    instructions += """
## General Best Practices

1. **SQL Injection:** Always use parameterized queries
2. **Secrets:** Use environment variables, never hardcode
3. **Eval/Exec:** Avoid completely, use safer alternatives
4. **Paths:** Validate and sanitize all file paths
5. **Crypto:** Use SHA-256 or stronger
6. **Random:** Use `secrets` module for security-critical operations
"""
    
    return instructions


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Python Security Scanner - Find vulnerabilities in your code"""
    pass


@main.command()
@click.argument("path", default=".")
@click.option("--output", "-o", type=click.Path(), help="Output report file")
@click.option("--format", "-f", type=click.Choice(["text", "json", "html"]), default="text", help="Report format")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), help="Filter by severity")
@click.option("--full", is_flag=True, help="Enable full scan (IaC, license, privacy, multilang)")
@click.option("--fix", is_flag=True, help="Automatically fix detected issues")
@click.option("--dry-run", is_flag=True, help="Show what would be fixed without making changes")
@click.option("--opencode", is_flag=True, help="Send issues to OpenCode for intelligent fixing")
@click.option("--rescan", is_flag=True, help="Rescan after OpenCode fixes")
@click.option("--cve", is_flag=True, help="Check for CVE vulnerabilities from database")
@click.option("--skip-test", is_flag=True, help="Skip test files in scan")
@click.option("--skip-example", is_flag=True, help="Skip example/demo/doc directories")
def scan(path, output, format, severity, full, fix, dry_run, opencode, rescan, cve, skip_test, skip_example):
    """Scan a project for security issues"""
    console.print(f"[bold blue]🔍 Starting security scan of {path}...[/bold blue]")
    
    console.print("[bold cyan]  📁 Scanning dependencies...[/bold cyan]")
    scanner = Scanner(path, full_scan=full, skip_test=skip_test, skip_example=skip_example)
    results = scanner.scan()
    console.print(f"[bold green]  ✓ Scanned {len(results)} potential issues[/bold green]")
    
    # Check for CVE vulnerabilities if requested
    cve_results = []
    if cve:
        console.print("[bold cyan]  📁 Checking CVE database...[/bold cyan]")
        from pysec.deps import scan_dependencies
        dep_issues = scan_dependencies(Path(path))
        
        # Use local CVE database
        from pysec.cve_db import check_cve
        for issue in dep_issues:
            pkg = issue.get("location", "")
            pkg_name = Path(pkg).stem if pkg else ""
            cve_result = check_cve(pkg_name, "")
            if cve_result:
                results.append({
                    "type": "vulnerable_dependency",
                    "severity": "high",
                    "description": f"{cve_result['cve']}: {cve_result['info'].get('description', 'Known vulnerability')}",
                    "location": pkg,
                    "fix": cve_result['info'].get('fix', 'Update package')
                })
        
        if cve_results:
            console.print(f"[bold red]⚠ Found {len(cve_results)} CVE vulnerabilities:[/bold red]")
            for cve in cve_results:
                console.print(f"  • {cve['type']}: {cve['package']} - {cve['description']}")
                console.print(f"    Fix: {cve['fix']}")
        else:
            console.print("[bold green]✓ No CVE vulnerabilities found[/bold green]")
    
    if severity:
        results = [r for r in results if r["severity"] == severity]
    
    if fix and results:
        console.print(f"[bold yellow]⚠ Found {len(results)} issues - attempting auto-fix...[/bold yellow]")
        try:
            from pysec.autofix import fix_issues, create_fix_suggestion
            import json
            
            scan_data = {"issues": results}
            target_dir = Path(path).absolute()
            
            if dry_run:
                console.print("[bold yellow]🔍 Dry run - showing fixes that would be applied:[/bold yellow]")
                for issue in results:
                    suggestion = create_fix_suggestion(issue)
                    console.print(f"  • {issue.get('type')}: {issue.get('location')}")
                    console.print(f"    → {suggestion}")
            else:
                fix_result = fix_issues(scan_data, target_dir)
                console.print(f"[bold green]✓ {fix_result['summary']}[/bold green]")
                
                # Rescan after fixes
                console.print("[bold blue]🔍 Rescanning after fixes...[/bold blue]")
                scanner = Scanner(path, full_scan=full)
                results = scanner.scan()
                if results:
                    console.print(f"[bold yellow]⚠ {len(results)} issues remain after auto-fix[/bold yellow]")
                else:
                    console.print("[bold green]✓ All issues fixed![/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error during auto-fix: {e}[/bold red]")
    
    # OpenCode integration
    if opencode and results:
        console.print(f"[bold blue]📤 Sending {len(results)} issues to OpenCode for intelligent fixing...[/bold blue]")
        
        # Generate fix instructions
        fix_instructions = generate_opencode_instructions(results)
        instructions_path = Path("/tmp/pysec_opencode_instructions.md")
        instructions_path.write_text(fix_instructions)
        
        # Create issues file for OpenCode
        issues_file = Path(path) / "security_issues.json"
        if Path(path).exists():
            import json
            issues_file.write_text(json.dumps({"issues": results}, indent=2))
        
        # Call OpenCode with detailed output
        import subprocess
        issue_count = len(results)
        high_count = len([r for r in results if r.get("severity") in ["high", "critical"]])
        medium_count = len([r for r in results if r.get("severity") == "medium"])
        low_count = len([r for r in results if r.get("severity") == "low"])
        
        issue_types = {}
        for r in results:
            t = r.get("type", "unknown")
            issue_types[t] = issue_types.get(t, 0) + 1
        
        type_summary = ", ".join([f"{v} {k}" for k, v in sorted(issue_types.items(), key=lambda x: -x[1])[:5]])
        
        msg = f"""Security Scan Results for {path}:

SUMMARY:
- Total Issues: {issue_count}
- Critical/High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

TOP ISSUES: {type_summary}

See /tmp/pysec_opencode_instructions.md for detailed fix instructions."""
        
        try:
            result = subprocess.run(
                f'opencode run "{msg}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=180
            )
            if result.returncode == 0:
                console.print(f"[bold green]✓ OpenCode invoked successfully[/bold green]")
                
                if rescan:
                    import time
                    console.print("[bold blue]⏳ Waiting for OpenCode to apply fixes...[/bold blue]")
                    for i in range(8):
                        time.sleep(5)
                        console.print(f"  ⌛ {40-i*5}s remaining...", end="\r")
                    console.print("\n")
                    
                    console.print("[bold blue]🔍 Rescanning...[/bold blue]")
                    scanner = Scanner(path, full_scan=full)
                    new_results = scanner.scan()
                    if new_results:
                        console.print(f"[bold yellow]⚠ {len(new_results)} issues remain[/bold yellow]")
                    else:
                        console.print("[bold green]✓ All issues fixed by OpenCode![/bold green]")
            else:
                console.print(f"[bold red]✗ OpenCode error: {result.stderr[:200]}[/bold red]")
        except subprocess.TimeoutExpired:
            console.print("[bold yellow]⚠ OpenCode timeout - may still be processing[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red]✗ Error invoking OpenCode: {e}[/bold red]")
    
    if format == "json":
        generate_json_report(results, output)
    elif format == "html":
        generate_html_report(results, output)
    else:
        display_results(results)
        if output:
            console.print(f"[yellow]Note: Use --format json or html to save to file[/yellow]")


@main.command()
@click.argument("package")
def check(package):
    """Check a specific package for vulnerabilities"""
    from pysec.deps import check_package
    
    console.print(f"[bold blue]Checking {package}...[/bold blue]")
    result = check_package(package)
    
    if result.get("vulns"):
        console.print(f"[bold red]✗ Found {len(result['vulns'])} vulnerabilities:[/bold red]")
        for vuln in result["vulns"]:
            console.print(f"  - {vuln}")
    else:
        console.print("[bold green]✓ No known vulnerabilities[/bold green]")


KNOWN_CVES = {
    "urllib3": {
        "CVE-2025-66418": {
            "description": "Unbounded decompression chain (DoS)",
            "affected": ">=1.24, <2.6.0",
            "fix": "urllib3>=2.6.0",
            "severity": "HIGH"
        }
    },
    "idna": {
        "CVE-2024-XXXX": {
            "description": "Check for latest CVEs",
            "fix": "idna>=3.6",
            "severity": "MEDIUM"
        }
    }
}


@main.command()
@click.argument("path", default=".")
def cve(path):
    """Check for known CVE vulnerabilities in dependencies"""
    from pysec.deps import scan_dependencies
    
    console.print(f"[bold blue]🔍 Checking for CVE vulnerabilities in {path}...[/bold blue]")
    
    issues = scan_dependencies(Path(path))
    cve_issues = []
    
    for issue in issues:
        pkg = issue.get("location", "")
        if "urllib3" in pkg.lower():
            cve_issues.append({
                "type": "CVE-2025-66418",
                "severity": "HIGH",
                "package": "urllib3",
                "description": "Unbounded decompression chain (DoS) - affects versions < 2.6.0",
                "fix": "Upgrade to urllib3>=2.6.0",
                "location": pkg
            })
    
    if cve_issues:
        console.print(f"[bold red]⚠ Found {len(cve_issues)} CVE vulnerabilities:[/bold red]")
        for cve in cve_issues:
            console.print(f"  • {cve['type']}: {cve['package']}")
            console.print(f"    Severity: {cve['severity']}")
            console.print(f"    Fix: {cve['fix']}")
            console.print(f"    Location: {cve['location']}")
    else:
        console.print("[bold green]✓ No known CVE vulnerabilities found[/bold green]")
    
    return cve_issues


@main.command()
@click.option("--format", "-f", type=click.Choice(["spdx", "cyclonedx", "json"]), default="json", help="SBOM format")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def sbom(format, output):
    """Generate Software Bill of Materials"""
    console.print(f"[bold blue]📦 Generating SBOM ({format})...[/bold blue]")
    
    try:
        if format == "spdx":
            from pysec.sbom import generate_sbom_spdx
            content = generate_sbom_spdx(output)
        elif format == "cyclonedx":
            from pysec.sbom import generate_sbom_cyclonedx
            content = generate_sbom_cyclonedx(output)
        else:
            from pysec.sbom import generate_sbom_json
            content = generate_sbom_json(output)
        
        if not output:
            console.print(content[:500])
        else:
            console.print(f"[green]SBOM saved to {output}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
def sast():
    """Run SAST tools (Bandit, Semgrep, Ruff)"""
    console.print("[bold blue]🔍 Running SAST tools...[/bold blue]")
    
    try:
        from pysec.sast import scan_all_sast
        results = scan_all_sast()
        
        for r in results:
            if "error" in r:
                console.print(f"[yellow]⚠ {r['error']}[/yellow]")
            else:
                sev = r.get("severity", "unknown")
                desc = r.get("description", "")
                loc = r.get("location", "")
                console.print(f"[{sev}]{sev.upper()}[/{sev}] {desc} @ {loc}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
@click.option("--dockerfile", default="Dockerfile", help="Dockerfile to scan")
def container(dockerfile):
    """Scan Dockerfiles and container images"""
    console.print(f"[bold blue]🐳 Scanning containers...[/bold blue]")
    
    try:
        from pysec.container import scan_container
        results = scan_container(dockerfile=dockerfile)
        
        for r in results:
            if "error" in r:
                console.print(f"[yellow]⚠ {r['error']}[/yellow]")
            else:
                sev = r.get("severity", "unknown")
                desc = r.get("description", "")
                loc = r.get("location", "")
                console.print(f"[{sev}]{sev.upper()}[/{sev}] {desc} @ {loc}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
def iac():
    """Scan Infrastructure as Code (Terraform, K8s, CloudFormation)"""
    console.print("[bold blue]🏗️ Scanning IaC...[/bold blue]")
    
    try:
        from pysec.iac import scan_iac
        results = scan_iac()
        
        for r in results:
            sev = r.get("severity", "unknown")
            desc = r.get("description", "")
            loc = r.get("location", "")
            console.print(f"[{sev}]{sev.upper()}[/{sev}] {desc} @ {loc}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
def license():
    """Check dependency licenses"""
    console.print("[bold blue]📜 Checking licenses...[/bold blue]")
    
    try:
        from pysec.license import scan_licenses
        results = scan_licenses()
        
        for r in results:
            sev = r.get("severity", "unknown")
            desc = r.get("description", "")
            loc = r.get("location", "")
            console.print(f"[{sev}]{sev.upper()}[/{sev}] {desc} @ {loc}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
def privacy():
    """Scan for PII and privacy issues"""
    console.print("[bold blue]🔐 Scanning for privacy issues...[/bold blue]")
    
    try:
        from pysec.privacy import scan_privacy
        results = scan_privacy()
        
        for r in results:
            sev = r.get("severity", "unknown")
            desc = r.get("description", "")
            loc = r.get("location", "")
            console.print(f"[{sev}]{sev.upper()}[/{sev}] {desc} @ {loc}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@main.command()
@click.option("--port", default=5000, help="Port to run dashboard")
@click.option("--results-dir", default="scan-results", help="Directory for scan results")
def serve(port, results_dir):
    """Start the pysec dashboard web server"""
    try:
        from pysec.dashboard import app, RESULTS_DIR
        import os
        os.environ["RESULTS_DIR"] = results_dir
        console.print(f"[bold green]Starting dashboard on http://localhost:{port}[/bold green]")
        app.run(host="0.0.0.0", port=port)
    except ImportError:
        console.print("[bold red]Error: Flask not installed. Install with: pip install pysec[dashboard][/bold red]")


if __name__ == "__main__":
    main()