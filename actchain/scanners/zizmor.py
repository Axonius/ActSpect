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
Zizmor scanner implementation for ActChain.
"""

import logging
import re
import subprocess
import sys
from typing import Dict, List, Any, Optional
import yaml

from .base import BaseScanner, ScannerError
from ..constants import SCANNER_TIMEOUT
from ..utils.security_utils import SecurityUtils

logger = logging.getLogger('actchain.scanners.zizmor')


class ZizmorScanner(BaseScanner):
    """Scanner implementation using Zizmor for GitHub Actions security scanning."""

    def __init__(self, min_severity: str = "low"):
        """Initialize the Zizmor scanner."""
        super().__init__(min_severity)
        self.scanner_name = "Zizmor Scanner"
        self._ensure_zizmor_available()

    def _ensure_zizmor_available(self) -> None:
        """Ensure Zizmor is available."""
        try:
            result = subprocess.run(
                ["zizmor", "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Found zizmor version: {result.stdout.strip()}")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try to install zizmor
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "zizmor"],
                check=True,
                timeout=60
            )
            logger.info("Successfully installed zizmor")
        except Exception as e:
            raise ScannerError(
                f"Zizmor is required but not available: {e}. "
                "Please install manually with 'pip install zizmor'"
            ) from e

    def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
        """Scan a workflow file using Zizmor."""
        scan_id = self.generate_scan_id()

        try:
            with SecurityUtils.secure_temp_file(suffix='.yml') as temp_file_path:
                # Write content to temp file
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Run Zizmor
                findings = self._run_zizmor_scan(temp_file_path, path)

            # Create report
            report = self.create_base_report(scan_id, path)
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning workflow with Zizmor: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan an action using Zizmor."""
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

                # Run Zizmor
                findings = self._run_zizmor_scan(temp_file_path, path)

            # Create report
            report = self.create_base_report(scan_id, path)
            report["action"] = ref
            report["type"] = action_data.get("type", "unknown")
            report["results"]["findings"] = findings
            return report

        except Exception as e:
            logger.error(f"Error scanning action with Zizmor: {e}")
            return self.create_error_report(scan_id, path, str(e))

    def _run_zizmor_scan(self, file_path: str, original_path: str) -> List[Dict[str, Any]]:
        """Run Zizmor scan on a file."""
        try:
            logger.info(f"Scanning with Zizmor: {original_path}")
            cmd = ["zizmor", "--format=plain", file_path]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=SCANNER_TIMEOUT
            )

            return self._parse_zizmor_output(result.stdout, original_path)

        except subprocess.TimeoutExpired:
            logger.error(f"Zizmor scan timed out for {original_path}")
            return []
        except subprocess.SubprocessError as e:
            logger.error(f"Zizmor process error: {e}")
            return []

    def _parse_zizmor_output(self, output: str, path: str) -> List[Dict[str, Any]]:
        """Parse Zizmor output into structured findings."""
        findings = []

        if not output or not output.strip():
            return findings

        # Pattern to match Zizmor findings
        finding_pattern = r'(error|warning|help|note)\[([^\]]+)\]:\s+(.*?)(?=(?:\n\s*-->|\n\n|\Z))'
        location_pattern = r'-->\s+([^:]+):(\d+):(\d+)'

        matches = re.finditer(finding_pattern, output, re.DOTALL)

        for match in matches:
            try:
                finding_type, audit_id, description = match.groups()
                description = description.strip()

                # Extract location information
                location = self._extract_location(output, match.end(), location_pattern)

                # Map to severity
                severity = self._map_zizmor_severity(finding_type, description)

                # Only include findings that meet the minimum severity level
                if self.should_include_finding(severity):
                    findings.append({
                        "rule_id": audit_id,
                        "title": f"{audit_id} issue",
                        "severity": severity,
                        "description": description,
                        "location": location or {"path": path, "line": 0, "column": 0},
                        "recommendation": f"Review the {audit_id} usage and fix according to Zizmor recommendations."
                    })
            except Exception as e:
                logger.error(f"Error parsing Zizmor finding: {e}")
                continue

        return findings

    def _extract_location(self, output: str, start_pos: int, pattern: str) -> Optional[Dict[str, Any]]:
        """Extract location information from Zizmor output."""
        location_text = output[start_pos:start_pos + 200]
        location_match = re.search(pattern, location_text)

        if location_match:
            try:
                file_path, line, col = location_match.groups()
                return {
                    "path": file_path.strip(),
                    "line": int(line),
                    "column": int(col)
                }
            except ValueError:
                return None
        return None

    def _map_zizmor_severity(self, finding_type: str, message: str) -> str:
        """Map Zizmor finding types to severity levels."""
        # Type-based mapping
        type_mapping = {
            "error": "high",
            "warning": "medium",
            "help": "low",
            "note": "low"
        }

        base_severity = type_mapping.get(finding_type, "medium")

        # Check message for severity indicators
        message_lower = message.lower()
        if "critical" in message_lower or "severe" in message_lower:
            return "critical"
        elif "high" in message_lower:
            return "high"

        return base_severity