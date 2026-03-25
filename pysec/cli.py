import click
from rich.console import Console
from pysec.scanner import Scanner

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Python Security Scanner - Find vulnerabilities in your code"""
    pass


@main.command()
@click.argument("path", default=".")
@click.option("--output", "-o", type=click.Path(), help="Output report file")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text", help="Report format")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), help="Filter by severity")
def scan(path, output, format, severity):
    """Scan a project for security issues"""
    console.print(f"[bold blue]🔍 Scanning {path}...[/bold blue]")
    
    scanner = Scanner(path)
    results = scanner.scan()
    
    if severity:
        results = [r for r in results if r["severity"] == severity]
    
    if format == "json":
        import json
        output_data = json.dumps(results, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(output_data)
        console.print(output_data)
    else:
        display_results(results, output)


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


def display_results(results, output_file=None):
    from rich.table import Table
    from rich.panel import Panel
    
    if not results:
        console.print(Panel.fit("[bold green]✓ No security issues found[/bold green]"))
        return
    
    table = Table(title="Security Issues Found")
    table.add_column("Severity", style="red")
    table.add_column("Type", style="cyan")
    table.add_column("Description")
    table.add_column("Location")
    
    for r in results:
        table.add_row(
            r.get("severity", "unknown").upper(),
            r.get("type", "unknown"),
            r.get("description", "")[:50],
            r.get("location", "")
        )
    
    console.print(table)
    
    summary = f"Found {len(results)} issue(s)"
    if output_file:
        summary += f" (saved to {output_file})"
    console.print(f"[bold]{summary}[/bold]")


if __name__ == "__main__":
    main()