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
File utilities for ActSpect.
"""

import logging
from pathlib import Path
from typing import Union, Optional

logger = logging.getLogger('actspect.utils.file')


class FileUtils:
    """Utilities for file operations."""

    @staticmethod
    def safe_write_file(content: str, file_path: Union[str, Path]) -> bool:
        """
        Safely write content to a file.

        Args:
            content: Content to write
            file_path: Path to the file

        Returns:
            True if successful, False otherwise
        """
        try:
            path_obj = Path(file_path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)

            with open(path_obj, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {e}")
            return False

    @staticmethod
    def safe_read_file(file_path: Union[str, Path]) -> Optional[str]:
        """
        Safely read content from a file.

        Args:
            file_path: Path to the file

        Returns:
            File content or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return None

    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Get file size in bytes."""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
