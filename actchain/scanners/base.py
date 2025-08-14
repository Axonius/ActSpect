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
Base scanner class for ActChain.
"""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any

from ..constants import SEVERITY_LEVELS


class ScannerError(Exception):
    """Custom exception for scanner errors."""
    pass


class BaseScanner(ABC):
    """Abstract base scanner class."""

    def __init__(self, min_severity: str = "low"):
        """
        Initialize the scanner.

        Args:
            min_severity: Minimum severity level to report
        """
        self.scanner_name = "Base Scanner"
        self.min_severity = min_severity.lower()
        self.min_severity_level = SEVERITY_LEVELS.get(self.min_severity, 1)

    @abstractmethod
    def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
        """
        Scan a workflow file.

        Args:
            content: Workflow file content
            path: Path to the workflow file

        Returns:
            Scan report dictionary
        """
        pass

    @abstractmethod
    def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan an action.

        Args:
            action_data: Action data to scan

        Returns:
            Scan report dictionary
        """
        pass

    def should_include_finding(self, severity: str) -> bool:
        """
        Determine if a finding should be included based on severity.

        Args:
            severity: Severity of the finding

        Returns:
            True if the finding should be included
        """
        severity_level = SEVERITY_LEVELS.get(severity.lower(), 1)
        return severity_level >= self.min_severity_level

    def create_base_report(self, scan_id: str, path: str) -> Dict[str, Any]:
        """Create a base report structure."""
        return {
            "id": scan_id,
            "path": path,
            "timestamp": datetime.now().isoformat(),
            "scanner": self.scanner_name,
            "results": {"findings": []}
        }

    def create_error_report(self, scan_id: str, path: str, error: str) -> Dict[str, Any]:
        """Create an error report."""
        report = self.create_base_report(scan_id, path)
        report["results"]["error"] = error
        return report

    def generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        return str(uuid.uuid4())