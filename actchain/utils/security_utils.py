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
Security utilities for ActChain.
"""

import os
import tempfile
import contextlib
import logging
import re

logger = logging.getLogger('actchain.utils.security')


class SecurityUtils:
    """Security-related utilities."""

    @staticmethod
    @contextlib.contextmanager
    def secure_temp_file(suffix: str = '', prefix: str = 'actchain_'):
        """
        Create a secure temporary file with proper cleanup.

        Args:
            suffix: File suffix
            prefix: File prefix

        Yields:
            Temporary file path
        """
        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix=suffix,
                prefix=prefix,
                delete=False
            )
            yield temp_file.name
        finally:
            if temp_file:
                temp_file.close()
                try:
                    os.unlink(temp_file.name)
                except OSError as e:
                    logger.warning(f"Failed to delete temporary file: {e}")

    @staticmethod
    def sanitize_for_log(message: str, max_length: int = 1000) -> str:
        """
        Sanitize message for logging to prevent information disclosure.

        Args:
            message: Original message
            max_length: Maximum length of sanitized message

        Returns:
            Sanitized message
        """
        # Pattern for GitHub tokens and similar secrets
        secret_patterns = [
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub personal access tokens
            r'ghs_[a-zA-Z0-9]{36}',  # GitHub server tokens
            r'github_pat_[a-zA-Z0-9_]{82}',  # GitHub fine-grained tokens
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 encoded secrets
        ]

        sanitized = message
        for pattern in secret_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized)

        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '...[TRUNCATED]'

        return sanitized