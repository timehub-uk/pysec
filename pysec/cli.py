import click
from rich.console import Console
from pysec.scanner import Scanner
from pysec.report import display_results, generate_json_report, generate_html_report

console = Console()


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
def scan(path, output, format, severity, full):
    """Scan a project for security issues"""
    console.print(f"[bold blue]🔍 Scanning {path}...[/bold blue]")
    
    scanner = Scanner(path, full_scan=full)
    results = scanner.scan()
    
    if severity:
        results = [r for r in results if r["severity"] == severity]
    
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