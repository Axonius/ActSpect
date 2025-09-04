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
Path utilities for ActSpect.
"""

import os
from pathlib import Path
from typing import Union


class PathUtils:
    """Utilities for path operations."""

    @staticmethod
    def validate_path(path: Union[str, Path]) -> Path:
        """
        Validate and normalize a file path.

        Args:
            path: File path to validate

        Returns:
            Normalized Path object
        """
        path_obj = Path(path).expanduser().resolve()
        return path_obj

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """
        Ensure directory exists, create if necessary.

        Args:
            path: Directory path

        Returns:
            Path object for the directory
        """
        path_obj = Path(path)
        path_obj.mkdir(parents=True, exist_ok=True)
        return path_obj

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename by replacing invalid characters and preventing path traversal.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename safe for filesystem operations
        """
        # First, strip any directory components to prevent path traversal
        filename = os.path.basename(filename)

        # Define invalid characters for filenames
        invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']

        # Replace invalid characters with underscores
        sanitized = filename
        for char in invalid_chars:
            sanitized = sanitized.replace(char, '_')

        # Handle edge cases
        if not sanitized or sanitized in ['.', '..']:
            sanitized = 'unnamed_file'

        return sanitized
