# Copyright (c) 2025 ActChain Development Team
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
Display utilities and main scanning logic for ActChain CLI.
"""

import os
import sys
import logging
from typing import Set, Dict, Any, List, Optional, Union
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich import box
import click

from ..core import GitHubClient, GitHubClientError, WorkflowParser, WorkflowParseError, ActionResolver
from ..scanners import get_scanner, ScannerError
from ..reports import ReportManager, ReportManagerError, convert_json_to_html
from ..utils.system_utils import SystemUtils

console = Console()
logger = logging.getLogger('actchain.cli.display')


class ActChainDisplay:
    """Handles display and scanning logic for ActChain CLI."""

    def __init__(self):
        """Initialize the display handler."""
        self.console = console

    def show_environment_info(self) -> None:
        """Display environment and dependency information."""
        self.console.print(Panel.fit(
            "[bold blue]GitHub Actions[/bold blue] Workflow Security Scanner\n"
            "[dim]Supply Chain Security Scanner[/dim]",
            title="ActChain",
            border_style="blue"
        ))

        # System information
        platform_info = SystemUtils.get_platform_info()
        self.console.print(Panel(
            f"[bold]System:[/bold] {platform_info['system']} {platform_info['release']}\n"
            f"[bold]Python:[/bold] {platform_info['python_version']}",
            title="System Information",
            border_style="blue"
        ))

        # Dependencies table
        env_report = SystemUtils.create_environment_report()
        deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependencies", title_style="bold blue")
        deps_table.add_column("Dependency", style="bold")
        deps_table.add_column("Status", justify="center")

        # Add dependency status
        for dep_name, is_available in env_report['dependencies'].items():
            status = "[green]✓ Installed[/green]" if is_available else "[red]✗ Not Found[/red]"
            deps_table.add_row(dep_name.capitalize(), status)

        # Environment variables
        env_vars = env_report['environment_variables']
        for var_name, is_set in env_vars.items():
            status = "[green]✓ Set[/green]" if is_set else "[red]✗ Not Set[/red]"
            deps_table.add_row(var_name, status)

        self.console.print(deps_table)

        # Help information
        self.console.print(Panel(
            "To scan a GitHub Actions workflow, use:\n"
            "[bold cyan]actchain scan --repo owner/repository[/bold cyan]\n\n"
            "For more options, use [bold]actchain scan --help[/bold]",
            title="Quick Help",
            border_style="blue"
        ))

    def run_scan(self, config: Dict[str, Any]) -> None:
        """
        Run the main workflow scanning process.

        Args:
            config: Configuration dictionary with scan parameters
        """
        try:
            # Display header
            self._display_header()

            # Initialize components
            components = self._initialize_components(config)

            # Get workflow(s) to scan
            workflow_info = self._get_workflow_to_scan(components, config)

            # Display scan configuration
            self._display_scan_config(config, workflow_info, components)

            # Perform the scan
            scan_results = self._perform_scan(components, workflow_info, config)

            # Display results
            self._display_scan_results(scan_results, components['report_manager'])

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise

    def _display_header(self) -> None:
        """Display the scan header."""
        self.console.print(Panel.fit(
            "[bold blue]GitHub Actions[/bold blue] Workflow Security Scanner\n"
            "[dim]Supply Chain Security Scanner[/dim]",
            title="ActChain",
            border_style="blue"
        ))

    def _initialize_components(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Initialize all required components."""
        components = {}

        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Initializing...[/bold blue]"),
                console=self.console
        ) as progress:
            task = progress.add_task("Connecting to GitHub", total=1)

            # Initialize GitHub client
            try:
                components['github_client'] = GitHubClient(config['token'], config['repo'])
            except GitHubClientError as e:
                raise Exception(f"Failed to connect to GitHub: {e}") from e

            # Initialize other components
            components['workflow_parser'] = WorkflowParser()
            components['action_resolver'] = ActionResolver(components['github_client'])

            # Initialize scanner(s)
            try:
                scanner_instances = get_scanner(config['scanner'], config['min_severity'])
                components['scanners'] = scanner_instances if isinstance(scanner_instances, list) else [
                    scanner_instances]
            except ScannerError as e:
                raise Exception(f"Failed to initialize scanners: {e}") from e

            # Initialize report manager
            try:
                components['report_manager'] = ReportManager(config['output_dir'])
            except ReportManagerError as e:
                raise Exception(f"Failed to initialize report manager: {e}") from e

            progress.update(task, advance=1)

        return components

    def _get_workflow_to_scan(self, components: Dict[str, Any], config: Dict[str, Any]) -> Union[
        Dict[str, Any], List[Dict[str, Any]]]:
        """Get the workflow(s) to scan (either specified or user selected)."""
        github_client = components['github_client']

        if config.get('workflow_path'):
            # Use specified workflow
            workflow_path = config['workflow_path']
            self.console.print(f"Fetching workflow: [bold cyan]{workflow_path}[/bold cyan]")

            try:
                with Progress(
                        SpinnerColumn(),
                        TextColumn("[bold blue]Fetching workflow...[/bold blue]"),
                        console=self.console
                ) as progress:
                    task = progress.add_task("Fetching", total=1)
                    workflow_content = github_client.get_file_content(workflow_path)
                    progress.update(task, advance=1)

                return {
                    "name": os.path.basename(workflow_path),
                    "path": workflow_path,
                    "content": workflow_content
                }
            except GitHubClientError as e:
                raise Exception(f"Failed to fetch workflow: {e}") from e
        elif config.get('scan_all_workflows'):
            # Scan all workflows without interactive selection
            return self._get_all_workflows_non_interactive(github_client)
        else:
            # Let user select workflow(s) interactively
            return self._select_workflow_interactively(github_client)

    def _get_all_workflows_non_interactive(self, github_client: GitHubClient) -> List[Dict[str, Any]]:
        """Get all workflows without interactive selection (for --scan-all-workflows flag)."""
        self.console.print("Fetching all workflows...")

        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflows = github_client.get_workflows()
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch workflows: {e}") from e

        if not workflows:
            raise Exception(f"No workflows found in {github_client.repo_name}")

        self.console.print(f"[bold green]Found {len(workflows)} workflows to scan[/bold green]")

        # Show list of workflows that will be scanned
        for i, workflow in enumerate(workflows, 1):
            self.console.print(f"  {i}. {workflow['name']}")

        return self._fetch_all_workflows(github_client, workflows)

    def _select_workflow_interactively(self, github_client: GitHubClient) -> Union[
        Dict[str, Any], List[Dict[str, Any]]]:
        """Let user select workflow(s) interactively."""
        self.console.print("Fetching available workflows...")

        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflows = github_client.get_workflows()
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch workflows: {e}") from e

        if not workflows:
            raise Exception(f"No workflows found in {github_client.repo_name}")

        # Display available workflows
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED,
                      title="Available Workflows", title_style="bold blue")
        table.add_column("#", style="dim", width=4)
        table.add_column("Workflow Name", style="cyan")
        table.add_column("Path", style="dim")

        # Add "All workflows" option
        table.add_row("0", "[bold green]Scan All Workflows[/bold green]", f"[dim]({len(workflows)} workflows)[/dim]")

        for i, workflow in enumerate(workflows, 1):
            table.add_row(str(i), workflow['name'], workflow['path'])

        self.console.print(table)

        # Get user selection
        max_selection = len(workflows)
        selection = click.prompt(
            f"Select a workflow to scan (0 for all, 1-{max_selection})",
            type=int,
            default=1
        )

        if selection < 0 or selection > max_selection:
            raise Exception("Invalid workflow selection")

        if selection == 0:
            # User selected "All workflows"
            self.console.print(f"[bold green]Selected:[/bold green] All {len(workflows)} workflows")
            return self._fetch_all_workflows(github_client, workflows)
        else:
            # User selected a specific workflow
            selected_workflow = workflows[selection - 1]
            self.console.print(f"[bold green]Selected:[/bold green] {selected_workflow['name']}")
            return self._fetch_single_workflow(github_client, selected_workflow)

    def _fetch_all_workflows(self, github_client: GitHubClient, workflows: List[Dict[str, str]]) -> List[
        Dict[str, Any]]:
        """Fetch content for all workflows."""
        workflow_data = []

        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Fetching workflows...[/bold blue]"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
        ) as progress:
            task = progress.add_task("Fetching", total=len(workflows))

            for workflow in workflows:
                try:
                    content = github_client.get_file_content(workflow['path'])
                    workflow_data.append({
                        "name": workflow['name'],
                        "path": workflow['path'],
                        "content": content
                    })
                    progress.update(task, advance=1, description=f"Fetched {workflow['name']}")
                except GitHubClientError as e:
                    logger.warning(f"Failed to fetch workflow {workflow['name']}: {e}")
                    progress.update(task, advance=1, description=f"Failed to fetch {workflow['name']}")
                    continue

        if not workflow_data:
            raise Exception("Failed to fetch any workflows")

        return workflow_data

    def _fetch_single_workflow(self, github_client: GitHubClient, workflow: Dict[str, str]) -> Dict[str, Any]:
        """Fetch content for a single workflow."""
        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Fetching selected workflow...[/bold blue]"),
                    console=self.console
            ) as progress:
                task = progress.add_task("Fetching", total=1)
                workflow_content = github_client.get_file_content(workflow['path'])
                progress.update(task, advance=1)
        except GitHubClientError as e:
            raise Exception(f"Failed to fetch selected workflow: {e}") from e

        return {
            "name": workflow['name'],
            "path": workflow['path'],
            "content": workflow_content
        }

    def _display_scan_config(self, config: Dict[str, Any], workflow_info: Union[Dict[str, Any], List[Dict[str, Any]]],
                             components: Dict[str, Any]) -> None:
        """Display scan configuration."""
        # Determine if we're scanning multiple workflows
        if isinstance(workflow_info, list):
            workflow_display = f"{len(workflow_info)} workflows"
            self.console.print(f"[bold green]✓[/bold green] Selected: [bold cyan]{workflow_display}[/bold cyan]")
        else:
            self.console.print(f"[bold green]✓[/bold green] Selected: [bold cyan]{workflow_info['name']}[/bold cyan]")

        # Get scanner names from components, not config
        scanner_names = [s.scanner_name for s in components.get('scanners', [])]
        scanner_display = ', '.join(scanner_names) if scanner_names else config.get('scanner', 'Unknown')

        self.console.print(Panel.fit(
            f"[bold]Scan Configuration:[/bold]\n"
            f"• Maximum Dependency Depth: {config['max_depth']}\n"
            f"• Scanner(s): {scanner_display}\n"
            f"• Minimum Severity: {config['min_severity']}\n"
            f"• Deep Scan: {'Enabled' if config.get('deep_scan') else 'Disabled'}\n"
            f"• Dependency Graph: {'Yes' if config.get('dependency_graph') else 'No'}",
            title="Configuration",
            border_style="blue"
        ))

    def _perform_scan(self, components: Dict[str, Any], workflow_info: Union[Dict[str, Any], List[Dict[str, Any]]],
                      config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform the actual scanning process."""
        processed_actions: Set[str] = set()
        action_count_by_depth: Dict[int, int] = {}
        all_main_findings: List[Dict[str, Any]] = []
        all_action_trees: List[Tree] = []

        # Determine if we're scanning multiple workflows
        workflows = workflow_info if isinstance(workflow_info, list) else [workflow_info]

        with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Scanning workflows...[/bold blue]"),
                BarColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                console=self.console
        ) as progress:
            main_task = progress.add_task("Overall progress", total=len(workflows) * 4)

            for workflow_idx, workflow in enumerate(workflows):
                workflow_name = workflow['name']

                # Parse workflow
                progress.update(main_task, description=f"Parsing {workflow_name}...")
                try:
                    workflow_data = self._parse_workflow(components['workflow_parser'], workflow['content'])
                    progress.update(main_task, advance=1)
                except Exception as e:
                    # Provide helpful error message for workflow parsing issues
                    if "workflow must have" in str(e).lower():
                        self.console.print(
                            f"\n[bold yellow]⚠️  Workflow Structure Issue in {workflow_name}[/bold yellow]")
                        self.console.print(Panel(
                            f"[bold red]Error:[/bold red] {str(e)}\n\n"
                            "[yellow]Possible causes:[/yellow]\n"
                            "• The file might be a workflow template or composite action\n"
                            "• The file might be malformed or incomplete\n"
                            "• The file might use an unsupported workflow format\n\n"
                            "[cyan]Suggestions:[/cyan]\n"
                            "• Check that the file is a complete GitHub Actions workflow\n"
                            "• Verify the file has 'on:' and 'jobs:' sections\n"
                            "• This workflow will be skipped",
                            title=f"Workflow Parsing Failed: {workflow_name}",
                            border_style="red"
                        ))
                    progress.update(main_task, advance=3)  # Skip remaining steps for this workflow
                    continue

                # Scan main workflow
                progress.update(main_task, description=f"Scanning {workflow_name}...")
                main_findings = self._scan_main_workflow(components, workflow, config)
                all_main_findings.extend(main_findings)
                progress.update(main_task, advance=1)

                # Extract actions
                progress.update(main_task, description=f"Extracting actions from {workflow_name}...")
                actions = components['workflow_parser'].extract_actions(workflow_data)
                progress.update(main_task, advance=1)

                # Build dependency tree and scan
                progress.update(main_task, description=f"Building dependency tree for {workflow_name}...")
                action_tree = self._build_and_scan_dependency_tree(
                    components, actions, config, processed_actions, action_count_by_depth, workflow_name
                )
                all_action_trees.append(action_tree)
                progress.update(main_task, advance=1)

            # Generate reports
            progress.update(main_task, description="Generating reports...")
            reports = self._generate_reports(
                components['report_manager'], all_action_trees, processed_actions,
                action_count_by_depth, config
            )

        return {
            'workflows_scanned': len(workflows),
            'workflows': workflows,
            'processed_actions': processed_actions,
            'action_count_by_depth': action_count_by_depth,
            'reports': reports,
            'main_findings': all_main_findings,
            'action_trees': all_action_trees
        }

    def _parse_workflow(self, workflow_parser: WorkflowParser, workflow_content: str) -> Dict[str, Any]:
        """Parse workflow content."""
        try:
            return workflow_parser.parse(workflow_content)
        except WorkflowParseError as e:
            raise Exception(f"Failed to parse workflow: {e}") from e

    def _scan_main_workflow(self, components: Dict[str, Any], workflow_info: Dict[str, Any], config: Dict[str, Any]) -> \
    List[Dict[str, Any]]:
        """Scan the main workflow with all scanners."""
        all_findings = []

        for scanner_index, scanner in enumerate(components['scanners']):
            try:
                report = scanner.scan_workflow(workflow_info['content'], workflow_info['path'])

                # Add scanner information to findings
                findings = report.get("results", {}).get("findings", [])
                for finding in findings:
                    finding["source_scanner"] = scanner.scanner_name
                    finding["workflow_name"] = workflow_info['name']  # Add workflow name for multi-workflow scans
                all_findings.extend(findings)

                # Save report with workflow name prefix for multi-workflow scans
                report_name = f"main_workflow_{workflow_info['name'].replace('.yml', '').replace('.yaml', '')}_{scanner_index}"
                components['report_manager'].save_report(report, report_name)

            except Exception as e:
                logger.error(f"Error scanning main workflow {workflow_info['name']} with {scanner.scanner_name}: {e}")

        return all_findings

    def _build_and_scan_dependency_tree(
            self,
            components: Dict[str, Any],
            actions: Set[str],
            config: Dict[str, Any],
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int],
            workflow_name: str
    ) -> Tree:
        """Build dependency tree and scan all actions."""
        action_tree = Tree(f"[bold]Workflow: {workflow_name} [dim]({len(actions)} actions)[/dim][/bold]")

        if not actions:
            return action_tree

        # Process each action in the workflow
        for action in actions:
            self._process_action_recursively(
                components, action, 0, action_tree, config['max_depth'],
                processed_actions, action_count_by_depth, config
            )

        # Save tree representation with workflow name
        tree_name = f"workflow_tree_{workflow_name.replace('.yml', '').replace('.yaml', '')}"
        components['report_manager'].save_workflow_tree(action_tree)

        return action_tree

    def _process_action_recursively(
            self,
            components: Dict[str, Any],
            action_ref: str,
            depth: int,
            parent_tree: Tree,
            max_depth: int,
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int],
            config: Dict[str, Any]
    ) -> None:
        """Process an action and its dependencies recursively."""
        logger.debug(f"Processing action {action_ref} at depth {depth}")

        # Update action count
        action_count_by_depth.setdefault(depth, 0)
        action_count_by_depth[depth] += 1

        # Check termination conditions
        if action_ref in processed_actions:
            parent_tree.add(f"[dim]{action_ref}[/dim] [dim](already processed)[/dim]")
            return

        if depth >= max_depth:
            parent_tree.add(f"[yellow]{action_ref}[/yellow] [dim](max depth reached)[/dim]")
            return

        # Skip Docker actions (no dependencies to scan)
        if action_ref.startswith('docker://'):
            parent_tree.add(f"[blue]{action_ref}[/blue] [dim](docker)[/dim]")
            return

        # Mark as processed
        processed_actions.add(action_ref)

        try:
            # Resolve action
            action_data = components['action_resolver'].resolve_action(action_ref)
            if not action_data:
                parent_tree.add(f"[red]{action_ref}[/red] [dim](not resolved)[/dim]")
                return

            # Scan action with all scanners
            all_findings = self._scan_action_with_all_scanners(
                components, action_data, action_ref, depth
            )

            # Add to tree with findings info
            has_findings = len(all_findings) > 0
            icon = "❌ " if has_findings else "✓ "
            findings_info = f"[red]({len(all_findings)} issues)[/red]" if has_findings else ""
            tree_item = parent_tree.add(
                f"{icon}[green]{action_ref}[/green] [dim](depth: {depth})[/dim] {findings_info}")

            # Process dependencies if not at max depth
            if depth < max_depth:
                self._process_action_dependencies(
                    components, action_data, action_ref, depth, tree_item,
                    max_depth, processed_actions, action_count_by_depth, config
                )

        except Exception as e:
            logger.error(f"Error processing action {action_ref}: {e}")
            parent_tree.add(f"[red]{action_ref}[/red] [dim](error: {str(e)})[/dim]")

    def _scan_action_with_all_scanners(
            self,
            components: Dict[str, Any],
            action_data: Dict[str, Any],
            action_ref: str,
            depth: int
    ) -> List[Dict[str, Any]]:
        """Scan an action with all available scanners."""
        all_findings = []

        for scanner_index, scanner in enumerate(components['scanners']):
            try:
                action_report = scanner.scan_action(action_data)

                # Add scanner information to findings
                findings = action_report.get("results", {}).get("findings", [])
                for finding in findings:
                    finding["source_scanner"] = scanner.scanner_name
                all_findings.extend(findings)

                # Save report
                report_name = f"action_{action_ref.replace('/', '_')}_depth_{depth}_{scanner_index}"
                components['report_manager'].save_report(action_report, report_name)

            except Exception as e:
                logger.error(f"Error scanning action {action_ref} with {scanner.scanner_name}: {e}")

        return all_findings

    def _process_action_dependencies(
            self,
            components: Dict[str, Any],
            action_data: Dict[str, Any],
            action_ref: str,
            depth: int,
            tree_item: Tree,
            max_depth: int,
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int],
            config: Dict[str, Any]
    ) -> None:
        """Process dependencies of an action."""
        # Get dependencies
        dependencies = components['action_resolver'].get_action_dependencies(
            action_data, components['workflow_parser']
        )

        if dependencies:
            logger.debug(f"Found {len(dependencies)} dependencies in {action_ref}")
            deps_group = tree_item.add("[cyan]Dependencies:[/cyan]")

            for dep in dependencies:
                self._process_action_recursively(
                    components, dep, depth + 1, deps_group, max_depth,
                    processed_actions, action_count_by_depth, config
                )
        else:
            logger.debug(f"No dependencies found in action {action_ref}")

    def _generate_reports(
            self,
            report_manager: ReportManager,
            action_trees: List[Tree],
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int],
            config: Dict[str, Any]
    ) -> Dict[str, Optional[str]]:
        """Generate consolidated and HTML reports."""
        reports = {}

        # Generate consolidated report
        consolidated_path = report_manager.generate_consolidated_report(
            processed_actions, action_count_by_depth
        )
        reports['consolidated'] = consolidated_path

        # Generate HTML report
        if consolidated_path:
            try:
                html_path = convert_json_to_html(consolidated_path)
                reports['html'] = html_path
                if html_path:
                    self.console.print(f"[bold green]✓[/bold green] HTML report generated: {html_path}")
            except Exception as e:
                logger.error(f"Failed to convert JSON to HTML: {e}")
                reports['html'] = None

        # Generate dependency graph if requested
        if config.get('dependency_graph'):
            graph_path = report_manager.generate_dependency_graph(
                processed_actions, action_count_by_depth
            )
            reports['graph'] = graph_path
            if graph_path:
                self.console.print(f"[bold green]✓[/bold green] Dependency graph generated: {graph_path}")

        return reports

    def _display_scan_results(self, scan_results: Dict[str, Any], report_manager: ReportManager) -> None:
        """Display scan results and summary."""
        # Display summary for multi-workflow scans
        workflows_scanned = scan_results.get('workflows_scanned', 1)
        if workflows_scanned > 1:
            self.console.print(f"\n[bold]Scanned {workflows_scanned} workflows:[/bold]")
            for workflow in scan_results.get('workflows', []):
                self.console.print(f"  • {workflow['name']}")

        # Display dependency trees
        self.console.print("\n[bold]Supply Chain Dependency Trees:[/bold]")
        action_trees = scan_results.get('action_trees', [])
        if len(action_trees) == 1:
            self.console.print(action_trees[0])
        else:
            for i, tree in enumerate(action_trees):
                self.console.print(f"\n[bold]Tree {i + 1}:[/bold]")
                self.console.print(tree)

        # Display summary
        self.console.print(Panel("[bold green]Scan Complete![/bold green]", border_style="green"))

        # Load and display statistics
        statistics = self._load_statistics(scan_results['reports'].get('consolidated'))

        # Create summary tables
        tables = self._create_summary_tables(statistics, scan_results)
        self.console.print(Columns(tables[:2], expand=True))
        if len(tables) > 2:
            self.console.print(tables[2])

        # Display report paths
        self._display_report_paths(scan_results['reports'])

    def _load_statistics(self, consolidated_path: Optional[str]) -> Dict[str, Any]:
        """Load statistics from consolidated report."""
        default_stats = {
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "scanner_counts": {}
        }

        if not consolidated_path:
            return default_stats

        try:
            import json
            with open(consolidated_path, 'r') as f:
                report_data = json.load(f)
                return report_data.get("statistics", default_stats)
        except Exception as e:
            logger.error(f"Failed to load statistics: {e}")
            return default_stats

    def _create_summary_tables(self, statistics: Dict[str, Any], scan_results: Dict[str, Any]) -> List[Table]:
        """Create summary tables for display."""
        tables = []

        # Findings table
        findings_table = Table(show_header=True, box=box.ROUNDED, title="Security Findings", title_style="bold red")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Count", justify="right")

        severity_counts = statistics.get("severity_counts", {})
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = severity_counts.get(severity.lower(), 0)
            color = {"Critical": "red", "High": "orange3", "Medium": "yellow", "Low": "green"}[severity]
            findings_table.add_row(severity, f"[bold {color}]{count}[/bold {color}]")

        total = severity_counts.get("total", 0)
        findings_table.add_row("Total", f"[bold]{total}[/bold]")
        tables.append(findings_table)

        # Scanner table
        scanner_table = Table(show_header=True, box=box.ROUNDED, title="Scanners Used", title_style="bold blue")
        scanner_table.add_column("Scanner", style="bold")
        scanner_table.add_column("Findings", justify="right")

        scanner_counts = statistics.get("scanner_counts", {})
        for scanner, count in scanner_counts.items():
            scanner_table.add_row(scanner, str(count))
        tables.append(scanner_table)

        # Dependencies table
        deps_table = Table(show_header=True, box=box.ROUNDED, title="Dependency Statistics", title_style="bold blue")
        deps_table.add_column("Metric", style="bold")
        deps_table.add_column("Value")

        action_count_by_depth = scan_results.get('action_count_by_depth', {})
        workflows_scanned = scan_results.get('workflows_scanned', 1)

        deps_table.add_row("Workflows Scanned", str(workflows_scanned))
        deps_table.add_row("Total Dependencies", str(len(scan_results.get('processed_actions', set()))))
        deps_table.add_row("Maximum Depth", str(max(action_count_by_depth.keys()) if action_count_by_depth else 0))

        for depth, count in sorted(action_count_by_depth.items()):
            deps_table.add_row(f"Actions at Depth {depth}", str(count))
        tables.append(deps_table)

        return tables

    def _display_report_paths(self, reports: Dict[str, Optional[str]]) -> None:
        """Display generated report paths."""
        reports_table = Table.grid(padding=(0, 1))
        reports_table.add_column(no_wrap=True)
        reports_table.add_column()

        if reports.get('consolidated'):
            reports_table.add_row(
                "[bold green]✓[/bold green]",
                f"Consolidated JSON report: [bold]{os.path.abspath(reports['consolidated'])}[/bold]"
            )

        if reports.get('html'):
            reports_table.add_row(
                "[bold green]✓[/bold green]",
                f"HTML report: [bold]{os.path.abspath(reports['html'])}[/bold]"
            )

        if reports.get('graph'):
            reports_table.add_row(
                "[bold green]✓[/bold green]",
                f"Dependency graph: [bold]{os.path.abspath(reports['graph'])}[/bold]"
            )

        self.console.print(Panel(
            reports_table,
            title="Generated Reports",
            border_style="green"
        ))