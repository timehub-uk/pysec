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
def scan(path, output, format, severity):
    """Scan a project for security issues"""
    console.print(f"[bold blue]🔍 Scanning {path}...[/bold blue]")
    
    scanner = Scanner(path)
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


if __name__ == "__main__":
    main()