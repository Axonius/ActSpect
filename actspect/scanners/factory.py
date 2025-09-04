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
Scanner factory for ActSpect.
"""

import logging
from typing import Union, List

from .base import BaseScanner, ScannerError
from .zizmor import ZizmorScanner
from .opengrep import OpenGrepScanner

logger = logging.getLogger('actspect.scanners.factory')


class ScannerFactory:
    """Factory for creating scanner instances."""

    @staticmethod
    def create_scanner(scanner_type: str, min_severity: str = "low") -> BaseScanner:
        """
        Create a scanner instance.

        Args:
            scanner_type: Type of scanner to create
            min_severity: Minimum severity level

        Returns:
            Scanner instance

        Raises:
            ScannerError: If scanner cannot be created
        """
        if scanner_type == "zizmor":
            return ZizmorScanner(min_severity)
        elif scanner_type == "opengrep":
            return OpenGrepScanner(min_severity)
        else:
            raise ScannerError(f"Unknown scanner type: {scanner_type}")


def get_scanner(scanner_type: str = "zizmor", min_severity: str = "low") -> Union[BaseScanner, List[BaseScanner]]:
    """
    Get scanner instance(s) based on the requested type.

    Args:
        scanner_type: Type of scanner ("zizmor", "opengrep", "all")
        min_severity: Minimum severity level

    Returns:
        Scanner instance or list of scanner instances

    Raises:
        ScannerError: If no scanners could be initialized
    """
    scanners = []

    if scanner_type in ["zizmor", "all"]:
        try:
            scanners.append(ScannerFactory.create_scanner("zizmor", min_severity))
            logger.info("Successfully initialized Zizmor scanner")
        except ScannerError as e:
            logger.warning(f"Could not initialize Zizmor scanner: {e}")

    if scanner_type in ["opengrep", "all"]:
        try:
            scanners.append(ScannerFactory.create_scanner("opengrep", min_severity))
            logger.info("Successfully initialized OpenGrep scanner")
        except ScannerError as e:
            logger.warning(f"Could not initialize OpenGrep scanner: {e}")

    if not scanners:
        try:
            # Fallback to Zizmor
            scanners.append(ScannerFactory.create_scanner("zizmor", min_severity))
            logger.warning("Using Zizmor scanner as fallback")
        except ScannerError as e:
            raise ScannerError(f"No scanners could be initialized: {e}") from e

    # Return single scanner if only one, otherwise return list
    return scanners[0] if len(scanners) == 1 else scanners
