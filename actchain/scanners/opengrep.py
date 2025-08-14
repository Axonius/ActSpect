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
OpenGrep scanner implementation for ActChain.
"""

import json
import logging
import re
import subprocess
from typing import Dict, List, Any
import yaml

from .base import BaseScanner, ScannerError
from ..constants import SCANNER_TIMEOUT, UNPINNED_ACTION_PATTERN
from ..utils.security_utils import SecurityUtils

logger = logging.getLogger('actchain.scanners.opengrep')


class OpenGrepScanner(BaseScanner):
    """Scanner implementation using OpenGrep for GitHub Actions security scanning."""

    def __init__(self, min_severity: str = "low"):
        """Initialize the OpenGrep scanner."""
        super().__init__(min_severity)
        self.scanner_name = "OpenGrep Scanner"
        self._ensure_opengrep_available()

    def _ensure_opengrep_available(self) -> None:
        """Ensure OpenGrep is available."""
        try:
            # Check if opengrep is available
            result = subprocess.run(
                ["opengrep", "--version"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                logger.info(f"Found OpenGrep version: {result.stdout.strip()}")
                return

            # If non-zero return code, log what happened
            logger.warning(f"OpenGrep version check failed with code {result.returncode}")
            if result.stderr:
                logger.warning(f"OpenGrep stderr: {result.stderr}")

        except FileNotFoundError:
            logger.warning("OpenGrep command not found.")
        except Exception as e:
            logger.warning(f"Error checking OpenGrep: {e}")

        # Provide clear installation instructions (from your working code)
        logger.error("OpenGrep is required but not installed. Please install it using one of these methods:")
        logger.error("1. Download from: https://github.com/opengrep/opengrep/releases")
        logger.error("2. Or install semgrep and create an alias: pip install semgrep && ln -s $(which semgrep) /usr/local/bin/opengrep")

        # Raise an exception that will be caught and handled in get_scanner()
        raise ScannerError("OpenGrep is required but not installed. Please install manually.")

    def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
        """Scan a workflow file using OpenGrep."""
        scan_id = self.generate_scan_id()

        try:
            with SecurityUtils.secure_temp_file(suffix='.yml') as temp_file_path:
                # Write content to temp file
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Run OpenGrep
                findings = self._run_opengrep_scan(temp_file_path, path)

                # Add fallback pattern matching if no findings
                if not findings:
                    findings.extend(self._fallback_pattern_scan(content, path))

            # Create report
            report = self.create_base_report(scan_id, path)
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning workflow with OpenGrep: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan an action using OpenGrep."""
        if not action_data or 'content' not in action_data:
            scan_id = self.generate_scan_id()
            ref = action_data.get("ref", "unknown") if action_data else "unknown"
            return self.create_error_report(scan_id, f"action_{ref}", "No content available")

        scan_id = self.generate_scan_id()
        ref = action_data.get("ref", "unknown")
        path = f"action_{ref}"

        try:
            with SecurityUtils.secure_temp_file(suffix='.yml') as temp_file_path:
                # Write action content to temp file
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(action_data['content'], f)

                # Run OpenGrep
                findings = self._run_opengrep_scan(temp_file_path, path)

                # Add fallback pattern matching if no findings
                if not findings:
                    action_content = yaml.dump(action_data['content'])
                    findings.extend(self._fallback_action_scan(action_content, path))

            # Create report
            report = self.create_base_report(scan_id, path)
            report["action"] = ref
            report["type"] = action_data.get("type", "unknown")
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning action with OpenGrep: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def _run_opengrep_scan(self, file_path: str, original_path: str) -> List[Dict[str, Any]]:
        """Run OpenGrep scan on a file."""
        try:
            logger.info(f"Scanning with OpenGrep: {original_path}")

            # Use the exact command structure from your working code
            cmd = [
                "opengrep", "scan",
                "--config", "p/github-actions",  # Use built-in rules for GitHub Actions
                "--json",
                "--error",  # Exit with code 1 if findings are found
                file_path
            ]

            logger.debug(f"OpenGrep command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=SCANNER_TIMEOUT
            )

            # Handle exit codes - code 1 means findings were found (due to --error flag)
            if result.returncode == 1:
                logger.debug(f"OpenGrep returned exit code 1, indicating findings were detected")
            elif result.returncode != 0:
                logger.warning(f"OpenGrep returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    logger.warning(f"OpenGrep stderr: {result.stderr[:500]}")

            return self._parse_opengrep_output(result.stdout, original_path)

        except subprocess.TimeoutExpired:
            logger.error(f"OpenGrep scan timed out for {original_path}")
            return []
        except subprocess.SubprocessError as e:
            logger.error(f"OpenGrep process error: {e}")
            return []

    def _parse_opengrep_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse OpenGrep output into structured findings."""
        findings = []

        if not output or not output.strip():
            logger.warning("Empty OpenGrep output")
            return findings

        # Log output for debugging
        logger.debug(f"OpenGrep raw output (first 500 chars): {output[:500]}")

        try:
            # Try to parse as JSON
            data = json.loads(output)
            logger.debug(f"Successfully parsed OpenGrep JSON with keys: {list(data.keys())}")

            # Check if the output has the expected structure
            if "results" in data:
                for result in data["results"]:
                    # Skip empty results
                    if not result:
                        continue

                    try:
                        # Extract basic info
                        check_id = result.get("check_id", "unknown").split(".")[-1]

                        # Get message and severity
                        extra = result.get("extra", {})
                        message = extra.get("message", "Unknown issue")
                        severity_str = extra.get("severity", "WARNING")

                        # Map severity using the same logic from your working code
                        severity = self._map_opengrep_severity(severity_str)

                        # Location information
                        file_path = result.get("path", path)
                        start = result.get("start", {})
                        line = start.get("line", 0)
                        col = start.get("col", 0)

                        # Create finding only if it meets the minimum severity
                        if self.should_include_finding(severity):
                            findings.append({
                                "rule_id": check_id,
                                "title": f"{check_id} issue",
                                "severity": severity,
                                "description": message,
                                "location": {
                                    "path": file_path,
                                    "line": line,
                                    "column": col
                                },
                                "recommendation": f"Review and fix the {check_id} issue",
                                "source_scanner": "OpenGrep Scanner"
                            })
                    except Exception as e:
                        logger.error(f"Error processing a finding: {e}")
                        continue

            elif "errors" in data and data["errors"]:
                logger.warning(f"OpenGrep reported errors: {data['errors']}")

        except json.JSONDecodeError:
            # If not JSON, try to parse as plain text (fallback from your working code)
            logger.debug("Failed to parse as JSON, trying plain text format")
            findings.extend(self._parse_opengrep_text_output(output, path))

        logger.info(f"Found {len(findings)} OpenGrep findings")
        return findings

    def _parse_opengrep_text_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse OpenGrep text output as fallback (from your working code)."""
        findings = []

        # Different formats OpenGrep might output
        formats = [
            # Format: file:line:column: message
            r'(.*?):(\d+):(\d+):(.*?)$',
            # Format: file:line: message
            r'(.*?):(\d+):(.*?)$',
            # Format with rule ID: file:line: [rule] message
            r'(.*?):(\d+):\s+\[(.*?)\](.*?)$'
        ]

        for line in output.strip().split('\n'):
            parsed = False
            for pattern in formats:
                match = re.match(pattern, line)
                if match:
                    try:
                        if len(match.groups()) == 4:  # file:line:column: message
                            file_path, line_num, col_num, message = match.groups()
                            rule_id = "unknown"
                        elif len(match.groups()) == 3:  # file:line: message or file:line: [rule] message
                            if '[' in match.group(3):  # Has rule ID
                                file_path, line_num = match.groups()[:2]
                                rule_match = re.search(r'\[(.*?)\](.*)', match.group(3))
                                if rule_match:
                                    rule_id, message = rule_match.groups()
                                else:
                                    rule_id, message = "unknown", match.group(3)
                                col_num = "0"
                            else:  # No rule ID
                                file_path, line_num, message = match.groups()
                                rule_id = "unknown"
                                col_num = "0"

                        # Default to medium severity
                        severity = "medium"
                        if "error" in message.lower():
                            severity = "high"
                        elif "warning" in message.lower():
                            severity = "medium"

                        # Add finding if it meets the minimum severity
                        if self.should_include_finding(severity):
                            findings.append({
                                "rule_id": rule_id,
                                "title": f"{rule_id} issue",
                                "severity": severity,
                                "description": message.strip(),
                                "location": {
                                    "path": file_path,
                                    "line": int(line_num),
                                    "column": int(col_num) if col_num.isdigit() else 0
                                },
                                "recommendation": "Review and fix the issue",
                                "source_scanner": "OpenGrep Scanner"
                            })
                        parsed = True
                        break
                    except Exception as e:
                        logger.error(f"Error parsing text output line: {e}")
                        continue

            if not parsed and line.strip():
                logger.debug(f"Unmatched line format: {line}")

        return findings

    def _map_opengrep_severity(self, severity_str: str) -> str:
        """Map OpenGrep severity to our severity levels (from your working code)."""
        if severity_str == "ERROR":
            return "high"
        elif severity_str == "WARNING":
            return "medium"
        elif severity_str == "INFO":
            return "low"
        else:
            return "medium"  # Default

    def _fallback_pattern_scan(self, content: str, path: str) -> List[Dict[str, Any]]:
        """Fallback pattern-based scanning for workflows (from your working code)."""
        findings = []

        # Check for unpinned actions (using @v1, @v2, etc. instead of commit hashes)
        unpinned_pattern = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@v\d+'
        for i, line in enumerate(content.split('\n')):
            match = re.search(unpinned_pattern, line)
            if match:
                severity = "high"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "unpinned-github-action",
                        "title": "Unpinned GitHub Action",
                        "severity": severity,
                        "description": f"GitHub Action {match.group(1)} uses version tag instead of commit hash",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": match.start()
                        },
                        "recommendation": "Pin GitHub Actions to specific commit hashes for better security",
                        "source_scanner": "OpenGrep Scanner"
                    })

        # Check for permissions: write-all
        permissions_pattern = r'permissions:\s+write-all'
        for i, line in enumerate(content.split('\n')):
            if re.search(permissions_pattern, line):
                severity = "medium"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "excessive-permissions",
                        "title": "Excessive Permissions",
                        "severity": severity,
                        "description": "Workflow uses overly broad write-all permissions",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": line.find("permissions")
                        },
                        "recommendation": "Use fine-grained permissions instead of write-all",
                        "source_scanner": "OpenGrep Scanner"
                    })

        # Check for artifact uploads (potential credential persistence)
        artifact_pattern = r'upload-artifact'
        for i, line in enumerate(content.split('\n')):
            if re.search(artifact_pattern, line):
                severity = "medium"
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": "artifact-credential-risk",
                        "title": "Artifact Credential Risk",
                        "severity": severity,
                        "description": "Potential credential persistence through GitHub Actions artifacts",
                        "location": {
                            "path": path,
                            "line": i + 1,
                            "column": line.find("upload-artifact")
                        },
                        "recommendation": "Ensure no credentials or sensitive data are persisted in artifacts",
                        "source_scanner": "OpenGrep Scanner"
                    })

        logger.debug(f"Manual pattern matching found {len(findings)} issues")
        return findings

    def _fallback_action_scan(self, content: str, path: str) -> List[Dict[str, Any]]:
        """Fallback pattern-based scanning for actions (from your working code)."""
        findings = []

        # Check for permissions issues
        if 'permissions' in content and 'write-all' in content:
            severity = "medium"
            if self.should_include_finding(severity):
                findings.append({
                    "rule_id": "excessive-permissions",
                    "title": "Excessive Permissions",
                    "severity": severity,
                    "description": "Action uses overly broad permissions",
                    "location": {
                        "path": path,
                        "line": 1,
                        "column": 1
                    },
                    "recommendation": "Use fine-grained permissions instead of write-all",
                    "source_scanner": "OpenGrep Scanner"
                })

        # Check for token usage
        if 'token' in content and 'github.token' in content:
            severity = "medium"
            if self.should_include_finding(severity):
                findings.append({
                    "rule_id": "token-exposure",
                    "title": "Token Exposure Risk",
                    "severity": severity,
                    "description": "GitHub token may be exposed in the action",
                    "location": {
                        "path": path,
                        "line": 1,
                        "column": 1
                    },
                    "recommendation": "Review token usage for security concerns",
                    "source_scanner": "OpenGrep Scanner"
                })

        logger.debug(f"Manual pattern matching found {len(findings)} issues")
        return findings