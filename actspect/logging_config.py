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
Logging configuration for ActSpect.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from .constants import MAX_LOG_SIZE


class ActSpectFilter(logging.Filter):
    """Custom filter for ActSpect logging."""

    def __init__(self, verbose: bool = False):
        """
        Initialize the filter.

        Args:
            verbose: Whether to enable verbose logging
        """
        super().__init__()
        self.verbose = verbose

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter logs based on verbosity and module.

        Args:
            record: Log record to filter

        Returns:
            True if log should be shown, False otherwise
        """
        # In verbose mode, show all logs
        if self.verbose:
            return True

        # Filter out debug logs from ActSpect modules unless verbose
        if record.name.startswith('actspect.') and record.levelno < logging.INFO:
            return False

        # Show all other logs
        return True


class LoggingConfig:
    """Configuration manager for logging."""

    @staticmethod
    def configure_logging(
            verbose: bool = False,
            log_file: Optional[str] = None,
            log_level: Optional[str] = None
    ) -> logging.Logger:
        """
        Configure logging for ActSpect.

        Args:
            verbose: Whether to enable verbose logging
            log_file: Path to log file (optional)
            log_level: Log level override

        Returns:
            Configured logger
        """
        # Determine log level
        if log_level:
            level = getattr(logging, log_level.upper(), logging.INFO)
        else:
            level = logging.DEBUG if verbose else logging.INFO

        # Create formatters
        console_formatter = LoggingConfig._get_console_formatter(verbose)
        file_formatter = LoggingConfig._get_file_formatter()

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)

        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Add console handler
        console_handler = LoggingConfig._create_console_handler(
            console_formatter, level, verbose
        )
        root_logger.addHandler(console_handler)

        # Add file handler if requested
        if log_file:
            file_handler = LoggingConfig._create_file_handler(
                log_file, file_formatter
            )
            if file_handler:
                root_logger.addHandler(file_handler)

        # Configure third-party loggers
        LoggingConfig._configure_third_party_loggers()

        return root_logger

    @staticmethod
    def _get_console_formatter(verbose: bool) -> logging.Formatter:
        """Create console formatter based on verbosity."""
        if verbose:
            return logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            )
        else:
            return logging.Formatter('%(message)s')

    @staticmethod
    def _get_file_formatter() -> logging.Formatter:
        """Create file formatter."""
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )

    @staticmethod
    def _create_console_handler(
            formatter: logging.Formatter,
            level: int,
            verbose: bool
    ) -> logging.StreamHandler:
        """Create and configure console handler."""
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        handler.setLevel(level)

        # Add custom filter
        handler.addFilter(ActSpectFilter(verbose=verbose))

        return handler

    @staticmethod
    def _create_file_handler(
            log_file: str,
            formatter: logging.Formatter
    ) -> Optional[logging.Handler]:
        """Create and configure file handler."""
        try:
            # Ensure log directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Use rotating file handler to manage log size
            handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=MAX_LOG_SIZE,
                backupCount=3,
                encoding='utf-8'
            )
            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)  # Always log everything to file

            return handler
        except Exception as e:
            # Use root logger here to avoid circular dependency
            logging.getLogger().error(f"Failed to set up log file: {e}")
            return None

    @staticmethod
    def _configure_third_party_loggers():
        """Configure third-party library loggers."""
        # Reduce noise from third-party libraries
        logging.getLogger('github').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)


def configure_logging(
        verbose: bool = False,
        log_file: Optional[str] = None,
        log_level: Optional[str] = None
) -> logging.Logger:
    """
    Convenience function to configure logging.

    Args:
        verbose: Enable verbose logging
        log_file: Path to log file
        log_level: Log level override

    Returns:
        Configured logger
    """
    return LoggingConfig.configure_logging(verbose, log_file, log_level)
