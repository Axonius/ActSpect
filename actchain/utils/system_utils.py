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
System utilities for ActChain.
"""

import os
import sys
import subprocess
import platform
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger('actchain.utils.system')


class SystemUtils:
    """Utilities for system operations."""

    @staticmethod
    def is_command_available(command: str) -> bool:
        """
        Check if a command is available on the system.

        Args:
            command: Command to check

        Returns:
            True if command is available, False otherwise
        """
        try:
            result = subprocess.run(
                [command, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def is_docker_available() -> bool:
        """Check if Docker is available on the system."""
        return SystemUtils.is_command_available("docker")

    @staticmethod
    def get_platform_info() -> Dict[str, str]:
        """Get information about the current platform."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }

    @staticmethod
    def check_dependencies() -> bool:
        """
        Check if all required dependencies are installed.

        Returns:
            True if all dependencies are available, False otherwise
        """
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("Python 3.8 or higher is required")
            return False

        # Check if git is installed
        if not SystemUtils.is_command_available("git"):
            logger.error("Git is required but not found")
            return False

        return True

    @staticmethod
    def get_env_var(name: str, default: Optional[str] = None) -> Optional[str]:
        """Get environment variable value."""
        return os.environ.get(name, default)

    @staticmethod
    def create_environment_report() -> Dict[str, Any]:
        """Create a comprehensive environment report."""
        return {
            "platform": SystemUtils.get_platform_info(),
            "dependencies": {
                "git": SystemUtils.is_command_available("git"),
                "docker": SystemUtils.is_docker_available(),
                "zizmor": SystemUtils.is_command_available("zizmor"),
            },
            "environment_variables": {
                "GITHUB_TOKEN": bool(SystemUtils.get_env_var("GITHUB_TOKEN")),
                "ACTCHAIN_LOG_LEVEL": SystemUtils.get_env_var("ACTCHAIN_LOG_LEVEL", "INFO"),
            }
        }