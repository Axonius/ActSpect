# Copyright (c) 2025 Axonius Solutions Ltd.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
CLI commands for ActSpect.
"""

import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich import box

from .. import __version__
from ..constants import (
    DEFAULT_MAX_DEPTH, DEFAULT_MIN_SEVERITY, DEFAULT_OUTPUT_DIR, SCANNER_TYPES
)
from ..logging_config import configure_logging
from ..utils.path_utils import PathUtils
from ..utils.system_utils import SystemUtils
from .display import ActSpectDisplay

console = Console()


class CLIError(Exception):
    """Custom exception for CLI errors."""
    pass


@click.group()
@click.version_option(version=__version__)
def cli():
    """ActSpect - Analyze GitHub Actions workflows and their dependencies for security issues."""
    pass


@cli.command()
@click.option('--repo', '-r', required=True, help='GitHub repository in the format "owner/repo"')
@click.option('--token', '-t', envvar='GITHUB_TOKEN', help='GitHub personal access token')
@click.option('--output-dir', '-o', default=DEFAULT_OUTPUT_DIR, help='Directory to save scan reports')
@click.option('--workflow-path', help='Path to a specific workflow file to scan')
@click.option('--scan-all-workflows', is_flag=True,
              help='Scan all workflows in the repository without interactive selection')
@click.option('--max-depth', type=int, default=DEFAULT_MAX_DEPTH, help='Maximum depth for recursive scanning')
@click.option('--scanner', type=click.Choice(SCANNER_TYPES), default='all',
              help='Scanner to use (all: use all available scanners, zizmor: Zizmor only, opengrep: OpenGrep only)')
@click.option('--min-severity', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default=DEFAULT_MIN_SEVERITY, help='Minimum severity level')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', '-d', is_flag=True, help='Enable debug mode')
@click.option('--deep-scan', is_flag=True, help='Enable deep scanning')
@click.option('--dependency-graph', is_flag=True, help='Generate dependency graph')
def scan(repo, token, output_dir, workflow_path, scan_all_workflows, max_depth, scanner, min_severity,
         verbose, debug, deep_scan, dependency_graph):
    """Scan GitHub Actions workflows and their dependencies."""

    # Configure logging
    configure_logging(verbose or debug,
                      log_file=f"{output_dir}/actspect_debug.log" if debug else None)

    # Validate required parameters
    if not token:
        console.print("[bold red]Error:[/bold red] GitHub token is required. Set GITHUB_TOKEN environment variable.")
        console.print("\n[yellow]To get a GitHub token:[/yellow]")
        console.print("1. Go to https://github.com/settings/tokens")
        console.print("2. Generate a new token with 'repo' scope")
        console.print("3. Set it as environment variable: export GITHUB_TOKEN='your_token'")
        sys.exit(1)

    # Validate repository format
    if not repo or '/' not in repo:
        console.print("[bold red]Error:[/bold red] Repository must be in 'owner/repo' format")
        console.print("[yellow]Example:[/yellow] --repo microsoft/actions")
        sys.exit(1)

    # Validate conflicting options
    if workflow_path and scan_all_workflows:
        console.print("[bold red]Error:[/bold red] Cannot use --workflow-path and --scan-all-workflows together")
        console.print("[yellow]Choose either:[/yellow]")
        console.print("  • --workflow-path to scan a specific workflow")
        console.print("  • --scan-all-workflows to scan all workflows")
        console.print("  • Neither to get interactive selection")
        sys.exit(1)

    # Show scanner information if using 'all'
    if scanner == 'all':
        _show_scanner_availability(verbose or debug)

    # Ensure output directory exists
    try:
        output_dir = str(PathUtils.validate_path(output_dir))
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Cannot create output directory: {e}")
        sys.exit(1)

    # Create configuration
    config = {
        'repo': repo,
        'token': token,
        'output_dir': output_dir,
        'workflow_path': workflow_path,
        'scan_all_workflows': scan_all_workflows,
        'max_depth': max_depth,
        'scanner': scanner,
        'min_severity': min_severity,
        'verbose': verbose,
        'debug': debug,
        'deep_scan': deep_scan,
        'dependency_graph': dependency_graph
    }

    # Show information about scan mode
    if scan_all_workflows:
        console.print("[bold blue]Mode:[/bold blue] Scanning all workflows in repository")
    elif workflow_path:
        console.print(f"[bold blue]Mode:[/bold blue] Scanning specific workflow: {workflow_path}")
    else:
        console.print("[bold blue]Mode:[/bold blue] Interactive workflow selection")

    # Initialize and run scan
    try:
        display = ActSpectDisplay()
        display.run_scan(config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if debug:
            import traceback
            console.print("\n[bold red]Traceback:[/bold red]")
            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
def info():
    """Display information about the environment and dependencies."""
    display = ActSpectDisplay()
    display.show_environment_info()


def _show_scanner_availability(verbose: bool = False):
    """Show which scanners are available when using 'all' option."""
    if not verbose:
        return

    console.print("\n[bold blue]Scanner Availability Check:[/bold blue]")

    scanner_table = Table(show_header=True, box=box.ROUNDED, title="Scanners", title_style="bold blue")
    scanner_table.add_column("Scanner", style="bold")
    scanner_table.add_column("Status", justify="center")
    scanner_table.add_column("Notes")

    # Check Zizmor
    try:
        from ..scanners.factory import ScannerFactory
        ScannerFactory.create_scanner("zizmor")
        scanner_table.add_row("Zizmor", "[green]✓ Available[/green]", "GitHub Actions security scanner")
    except Exception as e:
        scanner_table.add_row("Zizmor", "[red]✗ Not Available[/red]", f"Error: {str(e)[:50]}...")

    # Check OpenGrep/Semgrep
    try:
        ScannerFactory.create_scanner("opengrep")
        scanner_table.add_row("OpenGrep/Semgrep", "[green]✓ Available[/green]", "Static analysis tool")
    except Exception as e:
        scanner_table.add_row("OpenGrep/Semgrep", "[red]✗ Not Available[/red]", f"Error: {str(e)[:50]}...")

    console.print(scanner_table)
    console.print()


@cli.command()
@click.option('--install-all', is_flag=True, help='Install all optional scanner dependencies')
def setup(install_all):
    """Set up ActSpect and install optional dependencies."""
    console.print("[bold blue]ActSpect Setup[/bold blue]\n")

    # Check current environment
    env_report = SystemUtils.create_environment_report()

    # Show platform info
    platform_info = env_report['platform']
    console.print(f"[bold]Platform:[/bold] {platform_info['system']} {platform_info['release']}")
    console.print(f"[bold]Python:[/bold] {platform_info['python_version']}\n")

    # Show dependency status
    deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependencies", title_style="bold blue")
    deps_table.add_column("Dependency", style="bold")
    deps_table.add_column("Status", justify="center")
    deps_table.add_column("Action Needed")

    dependencies = env_report['dependencies']

    for dep_name, is_available in dependencies.items():
        if is_available:
            deps_table.add_row(dep_name.capitalize(), "[green]✓ Installed[/green]", "None")
        else:
            if dep_name == "zizmor":
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", "pip install zizmor")
            elif dep_name == "docker":
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", "Install Docker")
            else:
                deps_table.add_row(dep_name.capitalize(), "[red]✗ Missing[/red]", f"Install {dep_name}")

    console.print(deps_table)

    # Check environment variables
    env_vars = env_report['environment_variables']
    console.print("\n[bold]Environment Variables:[/bold]")
    for var_name, is_set in env_vars.items():
        status = "[green]✓ Set[/green]" if is_set else "[red]✗ Not Set[/red]"
        console.print(f"  {var_name}: {status}")

    if not env_vars.get('GITHUB_TOKEN'):
        console.print("\n[yellow]Warning:[/yellow] GITHUB_TOKEN not set. You'll need to provide it via --token option.")
        console.print("To set it: export GITHUB_TOKEN='your_token_here'")

    # Install optional dependencies if requested
    if install_all:
        console.print("\n[bold blue]Installing Optional Dependencies...[/bold blue]")
        _install_optional_dependencies()
    else:
        console.print("\n[dim]Tip: Use --install-all to install optional scanner dependencies[/dim]")


def _install_optional_dependencies():
    """Install optional dependencies for enhanced scanning."""
    import subprocess

    optional_packages = [
        ("semgrep", "OpenGrep/Semgrep scanner support"),
        ("graphviz", "Dependency graph generation")
    ]

    for package, description in optional_packages:
        try:
            console.print(f"Installing {package} ({description})...")
            subprocess.run([sys.executable, "-m", "pip", "install", package],
                           check=True, capture_output=True)
            console.print(f"[green]✓[/green] Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to install {package}: {e}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error installing {package}: {e}")


@cli.command()
@click.argument('scanner_type', type=click.Choice(['zizmor', 'opengrep', 'all']))
def test_scanner(scanner_type):
    """Test if a specific scanner is working correctly."""
    console.print(f"[bold blue]Testing {scanner_type} scanner(s)...[/bold blue]\n")

    try:
        from ..scanners.factory import get_scanner

        # Get scanner(s)
        scanners = get_scanner(scanner_type, "low")
        if not isinstance(scanners, list):
            scanners = [scanners]

        # Test each scanner
        for scanner in scanners:
            console.print(f"Testing {scanner.scanner_name}...")

            # Create a simple test workflow
            test_workflow = """
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Test step
        run: echo "Hello World"
"""

            try:
                result = scanner.scan_workflow(test_workflow, "test.yml")
                if "error" in result.get("results", {}):
                    console.print(f"[red]✗[/red] {scanner.scanner_name} failed: {result['results']['error']}")
                else:
                    findings_count = len(result.get("results", {}).get("findings", []))
                    console.print(f"[green]✓[/green] {scanner.scanner_name} working (found {findings_count} findings)")
            except Exception as e:
                console.print(f"[red]✗[/red] {scanner.scanner_name} error: {e}")

    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to test scanner: {e}")


@cli.command()
@click.option('--repo', '-r', required=True, help='GitHub repository in the format "owner/repo"')
@click.option('--token', '-t', envvar='GITHUB_TOKEN', help='GitHub personal access token')
def list_workflows(repo, token):
    """List all workflows in a repository."""
    if not token:
        console.print("[bold red]Error:[/bold red] GitHub token is required. Set GITHUB_TOKEN environment variable.")
        sys.exit(1)

    if not repo or '/' not in repo:
        console.print("[bold red]Error:[/bold red] Repository must be in 'owner/repo' format")
        sys.exit(1)

    try:
        from ..core.github_client import GitHubClient

        console.print(f"[bold blue]Fetching workflows from {repo}...[/bold blue]")

        # Initialize GitHub client
        github_client = GitHubClient(token, repo)
        workflows = github_client.get_workflows()

        if not workflows:
            console.print(f"[yellow]No workflows found in {repo}[/yellow]")
            return

        # Display workflows table
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED,
                      title=f"Workflows in {repo}", title_style="bold blue")
        table.add_column("#", style="dim", width=4)
        table.add_column("Workflow Name", style="cyan")
        table.add_column("Path", style="dim")

        for i, workflow in enumerate(workflows, 1):
            table.add_row(str(i), workflow['name'], workflow['path'])

        console.print(table)
        console.print(f"\n[bold]Total workflows found:[/bold] {len(workflows)}")
        console.print(
            "\n[dim]Tip: Use 'actspect scan --repo {repo} --scan-all-workflows' to scan all workflows[/dim]".format(
                repo=repo))

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
