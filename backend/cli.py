#!/usr/bin/env python3
"""
Akagami - Advanced Cybersecurity Toolkit CLI
Command-line interface for the comprehensive penetration testing toolkit
"""

import click
import json
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich import print as rprint

# Import our security modules
from modules.web_security import (
    ApplicationWalker, ContentDiscovery, SubdomainEnumerator,
    AuthBypass, IDORDetector, FileInclusionScanner,
    SSRFDetector, XSSScanner, RaceConditionTester,
    CommandInjectionTester, SQLInjectionScanner
)

console = Console()

@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version='1.0.0')
def cli(ctx):
    """
    ⚔️  AKAGAMI - Advanced Cybersecurity Penetration Testing Toolkit
    
    A powerful, organized cybersecurity toolkit with CLI and GUI interfaces.
    Features comprehensive web application security testing capabilities.
    
    ⚠️  LEGAL NOTICE: Use only on systems you own or have explicit permission to test.
    """
    console.print("""
[red bold]
    ██████╗ ██╗  ██╗ █████╗  ██████╗  █████╗ ███╗   ███╗██╗
   ██╔══██╗██║ ██╔╝██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██║
   ███████║█████╔╝ ███████║██║  ███╗███████║██╔████╔██║██║
   ██╔══██║██╔═██╗ ██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║
   ██║  ██║██║  ██╗██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║
   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝
[/red bold]

[bold white]Advanced Cybersecurity Penetration Testing Toolkit v1.0.0[/bold white]
[red]Created by: Security Research Team[/red]
[yellow]⚠️  For authorized testing only - Use responsibly[/yellow]
[dim]────────────────────────────────────────────────────────────[/dim]
""")
    
    if ctx.invoked_subcommand is None:
        console.print("\n[cyan]Use --help to see available commands[/cyan]")

@cli.command()
def cheats():
    """
    📚 AKAGAMI Cheats - Complete usage guide for all tools and modules
    """
    console.print("\n[bold red]📚 AKAGAMI CHEATS - Complete Usage Guide[/bold red]\n")
    
    # Current Tools Section
    console.print("[bold cyan]🔥 CURRENT TOOLS & MODULES[/bold cyan]")
    console.print("[dim]────────────────────────────────────────[/dim]")
    
    # Web Security Cheats
    console.print("\n[bold yellow]🌐 WEB SECURITY TESTING[/bold yellow]")
    
    # Reconnaissance
    console.print("\n[red]🔍 RECONNAISSANCE[/red]")
    console.print("┌─ Application Walker")
    console.print("│   [cyan]python3 cli.py web app-walker https://target.com[/cyan]")
    console.print("│   Maps application structure, endpoints, and technologies")
    console.print("│")
    console.print("├─ Subdomain Enumeration") 
    console.print("│   [cyan]python3 cli.py web subdomain-enum target.com[/cyan]")
    console.print("│   Discovers subdomains using DNS queries")
    console.print("│")
    console.print("└─ Content Discovery")
    console.print("    [cyan]python3 cli.py web content-discovery https://target.com[/cyan]")
    console.print("    Finds hidden files and directories")
    
    # Vulnerability Detection
    console.print("\n[red]🚨 VULNERABILITY DETECTION[/red]")
    console.print("┌─ XSS Scanner")
    console.print("│   [cyan]python3 cli.py web vuln-scan -m xss https://target.com[/cyan]")
    console.print("│   Tests for Cross-Site Scripting vulnerabilities")
    console.print("│")
    console.print("├─ SQL Injection Scanner")
    console.print("│   [cyan]python3 cli.py web vuln-scan -m sql_injection https://target.com[/cyan]")
    console.print("│   Advanced SQL injection detection")
    console.print("│")
    console.print("└─ SSRF Detection")
    console.print("    [cyan]python3 cli.py web vuln-scan -m ssrf https://target.com[/cyan]")
    console.print("    Server-Side Request Forgery testing")
    
    # Authentication & Authorization
    console.print("\n[red]🔐 AUTHENTICATION & AUTHORIZATION[/red]")
    console.print("┌─ Authentication Bypass")
    console.print("│   [cyan]python3 cli.py web vuln-scan -m auth_bypass https://target.com/login[/cyan]")
    console.print("│   Tests authentication bypass techniques")
    console.print("│")
    console.print("└─ IDOR Detection")
    console.print("    [cyan]python3 cli.py web vuln-scan -m idor https://target.com[/cyan]")
    console.print("    Insecure Direct Object Reference testing")
    
    # Injection Testing
    console.print("\n[red]💉 INJECTION TESTING[/red]")
    console.print("┌─ File Inclusion Scanner")
    console.print("│   [cyan]python3 cli.py web vuln-scan -m file_inclusion https://target.com[/cyan]")
    console.print("│   Tests for LFI/RFI vulnerabilities")
    console.print("│")
    console.print("└─ Command Injection")
    console.print("    [cyan]python3 cli.py web vuln-scan -m command_injection https://target.com[/cyan]")
    console.print("    OS command injection testing")
    
    # Logic Flaws
    console.print("\n[red]⚡ LOGIC FLAWS[/red]")
    console.print("└─ Race Condition Tester")
    console.print("    [cyan]python3 cli.py web vuln-scan -m race_conditions https://target.com[/cyan]")
    console.print("    Advanced race condition detection")
    
    # Advanced Usage
    console.print("\n[bold yellow]🚀 ADVANCED USAGE EXAMPLES[/bold yellow]")
    console.print("┌─ Multiple Module Scan")
    console.print("│   [cyan]python3 cli.py web vuln-scan -m xss,sql_injection https://target.com[/cyan]")
    console.print("│")
    console.print("├─ Custom Options")
    console.print("│   [cyan]python3 cli.py web app-walker https://target.com --depth 5 --threads 10[/cyan]")
    console.print("│")
    console.print("└─ Output to File")
    console.print("    [cyan]python3 cli.py web vuln-scan -m xss https://target.com > results.txt[/cyan]")
    
    # Coming Soon Section
    console.print("\n[bold magenta]🔮 COMING SOON - FUTURE MODULES[/bold magenta]")
    console.print("[dim]────────────────────────────────────────[/dim]")
    
    console.print("\n[yellow]🌐 NETWORK SCANNING[/yellow]")
    console.print("├─ Port Scanner: [dim]python3 cli.py network port-scan target.com[/dim]")
    console.print("├─ Service Detection: [dim]python3 cli.py network service-scan target.com[/dim]")
    console.print("└─ Network Discovery: [dim]python3 cli.py network discover 192.168.1.0/24[/dim]")
    
    console.print("\n[yellow]🔐 CRYPTO ANALYSIS[/yellow]")
    console.print("├─ Hash Cracker: [dim]python3 cli.py crypto crack-hash <hash>[/dim]")
    console.print("├─ Cipher Analysis: [dim]python3 cli.py crypto analyze-cipher <text>[/dim]")
    console.print("└─ Certificate Analysis: [dim]python3 cli.py crypto cert-analysis target.com[/dim]")
    
    console.print("\n[yellow]🕵️ DIGITAL FORENSICS[/yellow]")
    console.print("├─ File Analysis: [dim]python3 cli.py forensics analyze-file <file>[/dim]")
    console.print("├─ Metadata Extraction: [dim]python3 cli.py forensics metadata <file>[/dim]")
    console.print("└─ Memory Analysis: [dim]python3 cli.py forensics memory-dump <dump>[/dim]")
    
    console.print("\n[yellow]👥 SOCIAL ENGINEERING[/yellow]")
    console.print("├─ Phishing Generator: [dim]python3 cli.py social phishing-gen --template linkedin[/dim]")
    console.print("├─ Email Harvester: [dim]python3 cli.py social email-harvest domain.com[/dim]")
    console.print("└─ OSINT Gathering: [dim]python3 cli.py social osint-profile <target>[/dim]")
    
    console.print("\n[yellow]📱 MOBILE SECURITY[/yellow]")
    console.print("├─ APK Analysis: [dim]python3 cli.py mobile analyze-apk <file.apk>[/dim]")
    console.print("├─ iOS Security: [dim]python3 cli.py mobile ios-analysis <file.ipa>[/dim]")
    console.print("└─ Mobile OWASP: [dim]python3 cli.py mobile owasp-test <app>[/dim]")
    
    # GUI Access
    console.print("\n[bold green]🖥️ GUI ACCESS[/bold green]")
    console.print("[dim]────────────────────────────────────────[/dim]")
    console.print("Open GUI: [cyan]file:///home/daddyji/Project/akagami-red-gui.html[/cyan]")
    console.print("Backend API: [cyan]http://localhost:8001[/cyan]")
    
    # Tips & Tricks
    console.print("\n[bold blue]💡 TIPS & TRICKS[/bold blue]")
    console.print("[dim]────────────────────────────────────────[/dim]")
    console.print("• Use [cyan]python3 cli.py web list-modules[/cyan] to see all available modules")
    console.print("• Check module help: [cyan]python3 cli.py web vuln-scan --help[/cyan]")
    console.print("• Run multiple scans: Chain commands with [cyan]&&[/cyan]")
    console.print("• Save results: Redirect output with [cyan]>[/cyan] or [cyan]>>[/cyan]")
    console.print("• Background scans: Use [cyan]&[/cyan] at the end of commands")
    
    console.print("\n[red]⚠️  Remember: Only test on systems you own or have explicit permission![/red]")
    console.print("[dim]────────────────────────────────────────────────────────────────────[/dim]\n")

@cli.group()
def web():
    """Web application security testing tools"""
    pass

@web.command('list-modules')
def list_web_modules():
    """List all available web security testing modules organized by category"""
    
    # Define module categories like in the GUI
    categories = {
        "🔍 Reconnaissance": [
            ("Application Walker", "Comprehensive web application reconnaissance and structure mapping"),
            ("Subdomain Enumeration", "Intelligent subdomain discovery using DNS queries and wordlists"),
            ("Content Discovery", "Advanced directory and file enumeration scanner"),
        ],
        "🚨 Vulnerability Detection": [
            ("XSS Scanner", "Cross-Site Scripting vulnerability detection and exploitation"),
            ("SQL Injection Scanner", "Advanced SQL injection detection and exploitation framework"),
            ("SSRF Detection", "Server-Side Request Forgery vulnerability scanner"),
        ],
        "🔐 Authentication & Authorization": [
            ("Authentication Bypass", "Advanced authentication and authorization bypass testing"),
            ("IDOR Detection", "Insecure Direct Object Reference vulnerability scanner"),
        ],
        "💉 Injection Testing": [
            ("File Inclusion Scanner", "Local and Remote File Inclusion vulnerability detection"),
            ("Command Injection Tester", "OS command injection vulnerability scanner and exploiter"),
        ],
        "⚡ Logic Flaws": [
            ("Race Condition Tester", "Advanced race condition vulnerability detection and exploitation"),
        ]
    }
    
    rprint("\n[bold red]⚔️  AKAGAMI - Junior Pentest Modules[/bold red]\n")
    
    for category, modules in categories.items():
        # Create table for each category
        table = Table(title=f"{category}", show_header=True, header_style="bold red")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        
        for module_name, description in modules:
            table.add_row(module_name, description)
        
        console.print(table)
        console.print()  # Add spacing between categories
    table.add_column("Category", style="green")
    
    modules = [
        ("app-walker", "Walk and map web application structure", "Reconnaissance"),
        ("content-discovery", "Discover hidden files and directories", "Reconnaissance"),
        ("subdomain-enum", "Enumerate subdomains", "Reconnaissance"),
        ("auth-bypass", "Test authentication bypass", "Authentication"),
        ("idor", "Test for IDOR vulnerabilities", "Authorization"),
        ("file-inclusion", "Test for LFI/RFI vulnerabilities", "Injection"),
        ("ssrf", "Test for SSRF vulnerabilities", "Injection"),
        ("xss", "Test for XSS vulnerabilities", "Injection"),
        ("race-conditions", "Test for race conditions", "Logic"),
        ("command-injection", "Test for command injection", "Injection"),
        ("sql-injection", "Test for SQL injection", "Injection")
    ]
    
    for module, desc, category in modules:
        table.add_row(module, desc, category)
    
    console.print(table)

@web.command('app-walker')
@click.argument('target')
@click.option('--output', '-o', help='Output format (json/table)', default='table')
@click.option('--save', '-s', help='Save results to file')
def app_walker(target, output, save):
    """Walk and map web application structure"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(description="Walking application structure...", total=None)
        
        scanner = ApplicationWalker()
        results = scanner.scan(target)
        
        progress.update(task, description="✅ Scan completed!")
        
        if output == 'json':
            result_json = json.dumps(results, indent=2)
            console.print(Syntax(result_json, "json", theme="monokai"))
        else:
            _display_app_walker_results(results)
        
        if save:
            with open(save, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Results saved to {save}[/green]")

def _display_app_walker_results(results):
    """Display application walker results in a nice table format"""
    if 'error' in results:
        console.print(f"[red]Error: {results['error']}[/red]")
        return
    
    # Summary panel
    summary = Panel(
        f"[bold]Target:[/bold] {results['target']}\n"
        f"[bold]URLs Discovered:[/bold] {len(results.get('discovered_urls', []))}\n"
        f"[bold]Forms Found:[/bold] {len(results.get('forms', []))}\n"
        f"[bold]Technologies:[/bold] {', '.join(results.get('technologies', []))}\n"
        f"[bold]Execution Time:[/bold] {results.get('execution_time', 0):.2f}s",
        title="🔍 Application Walking Results",
        title_align="left"
    )
    console.print(summary)
    
    # Discovered URLs
    if results.get('crawled_pages'):
        table = Table(title="Crawled Pages")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Title", style="yellow")
        
        for page in results['crawled_pages'][:10]:  # Show first 10
            table.add_row(page['url'], str(page['status']), page['title'])
        
        console.print(table)

@web.command('content-discovery')
@click.argument('target')
@click.option('--output', '-o', help='Output format (json/table)', default='table')
@click.option('--save', '-s', help='Save results to file')
def content_discovery(target, output, save):
    """Discover hidden content and directories"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(description="Discovering hidden content...", total=None)
        
        scanner = ContentDiscovery()
        results = scanner.scan(target)
        
        progress.update(task, description="✅ Discovery completed!")
        
        if output == 'json':
            result_json = json.dumps(results, indent=2)
            console.print(Syntax(result_json, "json", theme="monokai"))
        else:
            _display_content_discovery_results(results)
        
        if save:
            with open(save, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Results saved to {save}[/green]")

def _display_content_discovery_results(results):
    """Display content discovery results"""
    if 'error' in results:
        console.print(f"[red]Error: {results['error']}[/red]")
        return
    
    summary = Panel(
        f"[bold]Target:[/bold] {results['target']}\n"
        f"[bold]Content Found:[/bold] {results.get('total_found', 0)}\n"
        f"[bold]Execution Time:[/bold] {results.get('execution_time', 0):.2f}s",
        title="📁 Content Discovery Results",
        title_align="left"
    )
    console.print(summary)
    
    if results.get('discovered_content'):
        table = Table(title="Discovered Content")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Content-Type", style="magenta")
        
        for content in results['discovered_content']:
            table.add_row(
                content['url'],
                str(content['status']),
                str(content['size']),
                content['content_type']
            )
        
        console.print(table)

@web.command('subdomain-enum')
@click.argument('target')
@click.option('--output', '-o', help='Output format (json/table)', default='table')
@click.option('--save', '-s', help='Save results to file')
def subdomain_enum(target, output, save):
    """Enumerate subdomains of target domain"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(description="Enumerating subdomains...", total=None)
        
        scanner = SubdomainEnumerator()
        results = scanner.scan(target)
        
        progress.update(task, description="✅ Enumeration completed!")
        
        if output == 'json':
            result_json = json.dumps(results, indent=2)
            console.print(Syntax(result_json, "json", theme="monokai"))
        else:
            _display_subdomain_results(results)
        
        if save:
            with open(save, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Results saved to {save}[/green]")

def _display_subdomain_results(results):
    """Display subdomain enumeration results"""
    summary = Panel(
        f"[bold]Target:[/bold] {results['target']}\n"
        f"[bold]Subdomains Found:[/bold] {results.get('total_found', 0)}\n"
        f"[bold]Execution Time:[/bold] {results.get('execution_time', 0):.2f}s",
        title="🌐 Subdomain Enumeration Results",
        title_align="left"
    )
    console.print(summary)
    
    if results.get('discovered_subdomains'):
        table = Table(title="Discovered Subdomains")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Method", style="yellow")
        
        for subdomain in results['discovered_subdomains']:
            table.add_row(
                subdomain['subdomain'],
                subdomain['ip'],
                subdomain['method']
            )
        
        console.print(table)

@web.command('vuln-scan')
@click.argument('target')
@click.option('--module', '-m', help='Specific vulnerability module to run')
@click.option('--output', '-o', help='Output format (json/table)', default='table')
@click.option('--save', '-s', help='Save results to file')
def vuln_scan(target, module, output, save):
    """Run vulnerability scans (auth-bypass, idor, xss, sqli, etc.)"""
    # Map of available vulnerability scanners
    scanners = {
        'auth-bypass': AuthBypass(),
        'idor': IDORDetector(),
        'file-inclusion': FileInclusionScanner(),
        'ssrf': SSRFDetector(),
        'xss': XSSScanner(),
        'race-conditions': RaceConditionTester(),
        'command-injection': CommandInjectionTester(),
        'sql-injection': SQLInjectionScanner()
    }
    
    if module and module not in scanners:
        console.print(f"[red]Unknown module: {module}[/red]")
        console.print(f"Available modules: {', '.join(scanners.keys())}")
        return
    
    modules_to_run = [module] if module else list(scanners.keys())
    all_results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        for mod in modules_to_run:
            task = progress.add_task(description=f"Running {mod} scan...", total=None)
            
            scanner = scanners[mod]
            results = scanner.scan(target)
            all_results[mod] = results
            
            progress.update(task, description=f"✅ {mod} scan completed!")
    
    if output == 'json':
        result_json = json.dumps(all_results, indent=2)
        console.print(Syntax(result_json, "json", theme="monokai"))
    else:
        _display_vulnerability_results(all_results)
    
    if save:
        with open(save, 'w') as f:
            json.dump(all_results, f, indent=2)
        console.print(f"[green]Results saved to {save}[/green]")
    # Map of available vulnerability scanners
    scanners = {
        'auth-bypass': AuthBypass(),
        'idor': IDORDetector(),
        'file-inclusion': FileInclusionScanner(),
        'ssrf': SSRFDetector(),
        'xss': XSSScanner(),
        'race-conditions': RaceConditionTester(),
        'command-injection': CommandInjectionTester(),
        'sql-injection': SQLInjectionScanner()
    }
    
    if module and module not in scanners:
        console.print(f"[red]Unknown module: {module}[/red]")
        console.print(f"Available modules: {', '.join(scanners.keys())}")
        return
    
    modules_to_run = [module] if module else list(scanners.keys())
    all_results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        for mod in modules_to_run:
            task = progress.add_task(description=f"Running {mod} scan...", total=None)
            
            scanner = scanners[mod]
            results = scanner.scan(target)
            all_results[mod] = results
            
            progress.update(task, description=f"✅ {mod} scan completed!")
    
    if output == 'json':
        result_json = json.dumps(all_results, indent=2)
        console.print(Syntax(result_json, "json", theme="monokai"))
    else:
        _display_vulnerability_results(all_results)
    
    if save:
        with open(save, 'w') as f:
            json.dump(all_results, f, indent=2)
        console.print(f"[green]Results saved to {save}[/green]")

def _display_vulnerability_results(all_results):
    """Display vulnerability scan results"""
    total_vulns = 0
    
    for module, results in all_results.items():
        vulns = results.get('vulnerabilities', [])
        total_vulns += len(vulns)
        
        if vulns:
            console.print(f"\n[bold red]🚨 {module.upper()} - {len(vulns)} vulnerabilities found[/bold red]")
            
            table = Table()
            table.add_column("Type", style="red")
            table.add_column("Risk", style="yellow")
            table.add_column("Description", style="white")
            table.add_column("Details", style="cyan")
            
            for vuln in vulns:
                details = vuln.get('url', vuln.get('payload', vuln.get('credentials', 'N/A')))
                table.add_row(
                    vuln.get('type', 'Unknown'),
                    vuln.get('risk', 'Unknown'),
                    vuln.get('description', 'No description'),
                    details
                )
            
            console.print(table)
        else:
            console.print(f"[green]✅ {module.upper()} - No vulnerabilities found[/green]")
    
    # Summary
    summary_panel = Panel(
        f"[bold]Total Vulnerabilities Found:[/bold] {total_vulns}\n"
        f"[bold]Modules Scanned:[/bold] {len(all_results)}",
        title="🔍 Vulnerability Scan Summary",
        title_align="left"
    )
    console.print(summary_panel)

@cli.command('server')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def server(host, port, reload):
    """Start the web API server"""
    try:
        import uvicorn
        console.print(f"[green]🚀 Starting CyberSec Toolkit API server on {host}:{port}[/green]")
        console.print(f"[cyan]📖 API documentation available at: http://{host}:{port}/docs[/cyan]")
        uvicorn.run("main:app", host=host, port=port, reload=reload)
    except ImportError:
        console.print("[red]Error: uvicorn not installed. Install with: pip install uvicorn[/red]")

@cli.command('gui')
def gui():
    """Launch the graphical user interface"""
    import webbrowser
    import subprocess
    import time
    
    console.print("[cyan]🖥️  Launching GUI...[/cyan]")
    
    # Start the backend server
    console.print("[yellow]Starting backend server...[/yellow]")
    subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"])
    
    # Give server time to start
    time.sleep(3)
    
    # Try to start frontend
    try:
        console.print("[yellow]Starting frontend...[/yellow]")
        subprocess.Popen(["npm", "start"], cwd="../frontend")
        time.sleep(5)
        
        # Open browser
        webbrowser.open("http://localhost:3000")
        console.print("[green]✅ GUI launched! Check your browser.[/green]")
        
    except FileNotFoundError:
        console.print("[yellow]Frontend not found. Opening API documentation instead...[/yellow]")
        webbrowser.open("http://localhost:8000/docs")

if __name__ == '__main__':
    cli()
