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
Report manager for ActSpect.
"""

import json
import logging
import re
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

from ..constants import REPORT_VERSION
from ..utils.path_utils import PathUtils
from ..utils.file_utils import FileUtils
from ..utils.system_utils import SystemUtils

logger = logging.getLogger('actspect.reports.manager')


class ReportManagerError(Exception):
    """Custom exception for report manager errors."""
    pass


class ReportManager:
    """Manages report generation and storage for ActSpect."""

    def __init__(self, output_dir: str):
        """
        Initialize the report manager.

        Args:
            output_dir: Directory to save reports

        Raises:
            ReportManagerError: If initialization fails
        """
        try:
            self.output_dir = PathUtils.validate_path(output_dir)
            self.scan_dir = self._create_scan_directory()
            self.reports: List[Dict[str, Any]] = []

            logger.info(f"Report manager initialized with output directory: {self.scan_dir}")
        except Exception as e:
            raise ReportManagerError(f"Failed to initialize report manager: {e}") from e

    def save_report(self, report: Dict[str, Any], name: str) -> Optional[str]:
        """
        Save a report to a file.

        Args:
            report: Report data
            name: Name for the report

        Returns:
            Path to the saved report or None if failed
        """
        try:
            # Sanitize filename
            safe_name = PathUtils.sanitize_filename(name)
            file_path = self.scan_dir / f"{safe_name}.json"

            # Save report
            if FileUtils.safe_write_file(json.dumps(report, indent=2), file_path):
                logger.debug(f"Saved report to {file_path}")
                self.reports.append({
                    "name": name,
                    "path": str(file_path),
                    "data": report
                })
                return str(file_path)
            else:
                logger.error(f"Failed to save report {name}")
                return None

        except Exception as e:
            logger.error(f"Error saving report {name}: {e}")
            return None

    def save_workflow_tree(self, tree_text: Any) -> Optional[str]:
        """
        Save the workflow dependency tree representation.

        Args:
            tree_text: Tree text representation or Rich Tree object

        Returns:
            Path to the saved tree file or None if failed
        """
        file_path = self.scan_dir / "workflow_tree.txt"

        try:
            # Handle Rich Tree objects
            if hasattr(tree_text, '__rich__') or 'rich.tree.Tree' in str(type(tree_text)):
                content = self._render_rich_tree(tree_text)
            else:
                content = str(tree_text)

            if FileUtils.safe_write_file(content, file_path):
                logger.debug(f"Saved workflow tree to {file_path}")
                return str(file_path)
            else:
                return None

        except Exception as e:
            logger.error(f"Failed to save workflow tree: {e}")
            return None

    def generate_consolidated_report(
            self,
            processed_actions: Optional[Set[str]] = None,
            action_count_by_depth: Optional[Dict[int, int]] = None
    ) -> Optional[str]:
        """
        Generate a comprehensive consolidated report.

        Args:
            processed_actions: Set of processed actions from CLI
            action_count_by_depth: Action count by depth from CLI

        Returns:
            Path to the consolidated report or None if failed
        """
        file_path = self.scan_dir / "consolidated_report.json"

        try:
            # Create consolidated report structure
            consolidated = self._create_consolidated_structure()

            # Process workflow and dependency data
            self._process_workflow_data(consolidated)
            self._process_dependency_data(consolidated, processed_actions, action_count_by_depth)
            self._process_findings_data(consolidated)

            # Save consolidated report
            if FileUtils.safe_write_file(json.dumps(consolidated, indent=2), file_path):
                logger.info(f"Generated consolidated report: {file_path}")
                return str(file_path)
            else:
                return None

        except Exception as e:
            logger.error(f"Failed to generate consolidated report: {e}")
            return None

    def generate_dependency_graph(
            self,
            processed_actions: Set[str],
            action_count_by_depth: Dict[int, int]
    ) -> Optional[str]:
        """
        Generate a dependency graph visualization.

        Args:
            processed_actions: Set of processed actions
            action_count_by_depth: Action count by depth

        Returns:
            Path to the generated graph file or None if failed
        """
        if not SystemUtils.is_command_available("dot"):
            logger.warning("Graphviz not installed, cannot generate dependency graph")
            return None

        dot_path = self.scan_dir / "dependency_graph.dot"
        png_path = self.scan_dir / "dependency_graph.png"

        try:
            # Generate DOT file
            dot_content = self._generate_dot_content(processed_actions)
            if not FileUtils.safe_write_file(dot_content, dot_path):
                return None

            # Generate PNG
            try:
                subprocess.run(
                    ["dot", "-Tpng", str(dot_path), "-o", str(png_path)],
                    check=True,
                    timeout=60
                )
                logger.info(f"Generated dependency graph: {png_path}")
                return str(png_path)
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                logger.error(f"Failed to run dot: {e}")
                return str(dot_path)

        except Exception as e:
            logger.error(f"Error generating dependency graph: {e}")
            return None

    def _create_scan_directory(self) -> Path:
        """Create a unique scan directory for this run."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = str(uuid.uuid4())[:8]
        scan_dir = self.output_dir / f"scan_{timestamp}_{scan_id}"

        try:
            scan_dir.mkdir(parents=True, exist_ok=True)
            return scan_dir
        except Exception as e:
            raise ReportManagerError(f"Failed to create scan directory: {e}") from e

    def _render_rich_tree(self, tree_text: Any) -> str:
        """Render Rich Tree object to string."""
        try:
            from rich.console import Console
            import io

            string_io = io.StringIO()
            console = Console(file=string_io, width=120)
            console.print(tree_text)
            return string_io.getvalue()
        except Exception as e:
            logger.error(f"Failed to render Rich tree: {e}")
            return str(tree_text)

    def _create_consolidated_structure(self) -> Dict[str, Any]:
        """Create the base structure for consolidated report."""
        return {
            "meta": {
                "timestamp": datetime.now().isoformat(),
                "scan_id": self.scan_dir.name,
                "total_reports": len(self.reports),
                "report_version": REPORT_VERSION
            },
            "workflow": {},
            "findings": [],
            "dependencies": [],
            "statistics": {
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
                "dependency_counts": {"total": 0, "by_depth": {}},
                "scanner_counts": {}
            }
        }

    def _process_workflow_data(self, consolidated: Dict[str, Any]) -> None:
        """Process workflow data from reports."""
        main_workflow = self._get_main_workflow_report()
        if main_workflow:
            workflow_data = main_workflow["data"]
            consolidated["workflow"] = {
                "name": Path(workflow_data.get("workflow_path", workflow_data.get("path", "unknown"))).name,
                "path": workflow_data.get("workflow_path", workflow_data.get("path", "unknown")),
                "scan_timestamp": workflow_data.get("timestamp", datetime.now().isoformat())
            }

    def _process_dependency_data(
            self,
            consolidated: Dict[str, Any],
            processed_actions: Optional[Set[str]],
            action_count_by_depth: Optional[Dict[int, int]]
    ) -> None:
        """Process dependency data."""
        unique_dependencies = self._extract_unique_dependencies()
        consolidated["dependencies"] = list(unique_dependencies.values())

        # Use provided statistics if available
        if processed_actions is not None and action_count_by_depth is not None:
            consolidated["statistics"]["dependency_counts"]["total"] = len(processed_actions)
            consolidated["statistics"]["dependency_counts"]["by_depth"] = {
                str(depth): count for depth, count in action_count_by_depth.items()
            }
        else:
            # Fallback to calculated statistics
            consolidated["statistics"]["dependency_counts"]["total"] = len(unique_dependencies)
            depth_counts = {}
            for dep in unique_dependencies.values():
                depth = str(dep["depth"])
                depth_counts[depth] = depth_counts.get(depth, 0) + 1
            consolidated["statistics"]["dependency_counts"]["by_depth"] = depth_counts

    def _process_findings_data(self, consolidated: Dict[str, Any]) -> None:
        """Process findings data from all reports."""
        for report in self.reports:
            findings = report["data"].get("results", {}).get("findings", [])

            for finding in findings:
                # Ensure scanner information is present
                if "source_scanner" not in finding:
                    finding["source_scanner"] = self._infer_scanner_from_report(report["name"])

                # Add source information
                finding["source"] = self._get_finding_source(report)

                # Add to consolidated findings
                consolidated["findings"].append(finding)

                # Update statistics
                self._update_finding_statistics(consolidated["statistics"], finding)

    def _get_main_workflow_report(self) -> Optional[Dict[str, Any]]:
        """Get the main workflow report."""
        return next(
            (r for r in self.reports if r["name"].startswith("main_workflow")),
            None
        )

    def _extract_unique_dependencies(self) -> Dict[str, Dict[str, Any]]:
        """Extract unique dependencies from reports with improved metadata parsing."""
        unique_dependencies = {}

        for report in self.reports:
            if not report["name"].startswith("main_workflow"):
                # Try to get action reference from report metadata first (more reliable)
                action_ref = self._get_action_ref_from_report_data(report)

                # Fallback to filename parsing only if metadata not available
                if not action_ref:
                    action_ref = self._extract_action_ref_from_report_name(report["name"])

                if action_ref and action_ref not in unique_dependencies:
                    depth = self._extract_depth_from_report_name(report["name"])
                    action_type = self._get_action_type_from_report_data(report)

                    unique_dependencies[action_ref] = {
                        "name": action_ref,
                        "type": action_type,
                        "depth": depth,
                        "findings_count": 0,
                        "scanner_reports": []
                    }

                # Update findings count
                if action_ref in unique_dependencies:
                    findings = report["data"].get("results", {}).get("findings", [])
                    unique_dependencies[action_ref]["findings_count"] += len(findings)
                    unique_dependencies[action_ref]["scanner_reports"].append(report["name"])

        return unique_dependencies

    def _get_action_ref_from_report_data(self, report: Dict[str, Any]) -> Optional[str]:
        """Get action reference from report metadata (preferred method)."""
        report_data = report.get("data", {})

        # Check for action_ref field added by improved scanners
        action_ref = report_data.get("action_ref")
        if action_ref:
            logger.debug(f"Found action_ref in report data: {action_ref}")
            return action_ref

        # Fallback to legacy action field
        action_ref = report_data.get("action")
        if action_ref:
            logger.debug(f"Found action field in report data: {action_ref}")
            return action_ref

        return None

    def _get_action_type_from_report_data(self, report: Dict[str, Any]) -> str:
        """Get action type from report metadata."""
        report_data = report.get("data", {})

        # Check for action_type field added by improved scanners
        action_type = report_data.get("action_type")
        if action_type:
            return action_type

        # Fallback to legacy type field
        return report_data.get("type", "unknown")

    def _extract_action_ref_from_report_name(self, report_name: str) -> Optional[str]:
        """
        Extract action reference from report name (fallback method).

        This method is kept as a fallback for backward compatibility,
        but the preferred method is to use metadata from report data.
        """
        logger.debug(f"Using fallback filename parsing for report: {report_name}")

        if not report_name.startswith("action_"):
            return None

        # Parse name like "action_actions_checkout_v3_depth_0_0"
        parts = report_name.split("_")
        if len(parts) >= 4:
            # Look for owner/repo pattern
            for i in range(1, len(parts) - 2):
                if parts[i] in ["actions", "docker", "github", "cycjimmy"] and i + 1 < len(parts):
                    owner = parts[i]
                    repo_parts = []
                    version_part = None

                    # Collect repo name parts
                    for j in range(i + 1, len(parts)):
                        if parts[j].startswith("v") and parts[j][1:].isdigit():
                            version_part = parts[j]
                            break
                        elif parts[j] == "depth":
                            break
                        else:
                            repo_parts.append(parts[j])

                    if repo_parts:
                        repo = "-".join(repo_parts)
                        if version_part:
                            return f"{owner}/{repo}@{version_part}"
                        else:
                            return f"{owner}/{repo}"

        return None

    def _extract_depth_from_report_name(self, report_name: str) -> int:
        """Extract depth from report name."""
        depth_match = re.search(r'depth_(\d+)', report_name)
        return int(depth_match.group(1)) if depth_match else 0

    def _infer_scanner_from_report(self, report_name: str) -> str:
        """Infer scanner name from report name."""
        if "_0" in report_name:
            return "Zizmor Scanner"
        elif "_1" in report_name:
            return "OpenGrep Scanner"
        else:
            return "Unknown Scanner"

    def _get_finding_source(self, report: Dict[str, Any]) -> Dict[str, str]:
        """Get source information for a finding."""
        report_data = report.get("data", {})

        # Use workflow_path or action_ref if available, otherwise fall back to path
        path = (report_data.get("workflow_path") or
                report_data.get("action_ref") or
                report_data.get("path", "unknown"))

        return {
            "name": report["name"],
            "path": path
        }

    def _update_finding_statistics(self, statistics: Dict[str, Any], finding: Dict[str, Any]) -> None:
        """Update statistics with finding information."""
        # Update severity counts
        severity = finding.get("severity", "low").lower()
        if severity in statistics["severity_counts"]:
            statistics["severity_counts"][severity] += 1
        statistics["severity_counts"]["total"] += 1

        # Update scanner counts
        scanner_name = finding.get("source_scanner", "unknown")
        if scanner_name not in statistics["scanner_counts"]:
            statistics["scanner_counts"][scanner_name] = 0
        statistics["scanner_counts"][scanner_name] += 1

    def _generate_dot_content(self, processed_actions: Set[str]) -> str:
        """Generate DOT file content for dependency graph."""
        lines = [
            'digraph DependencyGraph {',
            '  rankdir=LR;',
            '  node [shape=box, style="filled", fillcolor=lightblue];',
            ''
        ]

        # Add nodes
        for action in processed_actions:
            node_id = self._sanitize_node_id(action)
            lines.append(f'  "{node_id}" [label="{action}"];')

        lines.append('}')
        return '\n'.join(lines)

    def _sanitize_node_id(self, action_ref: str) -> str:
        """Sanitize action reference for use as node ID."""
        return re.sub(r'[^a-zA-Z0-9_]', '_', action_ref)
