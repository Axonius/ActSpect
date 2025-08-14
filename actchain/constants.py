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
Constants and configuration for ActChain.
"""

# Scanning configuration
DEFAULT_MAX_DEPTH = 5
DEFAULT_MIN_SEVERITY = 'low'
DEFAULT_OUTPUT_DIR = './actchain_reports'

# Severity levels (higher number = more severe)
SEVERITY_LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'unknown': 0
}

# Known dependencies for popular actions
KNOWN_ACTION_DEPENDENCIES = {
    "docker/build-push-action": [
        "docker/setup-buildx-action",
        "docker/login-action",
        "docker/metadata-action"
    ],
    "actions/cache": [
        "actions/cache/save",
        "actions/cache/restore"
    ],
    "actions/checkout": [],
    "github/super-linter": [
        "actions/checkout"
    ],
    "actions/setup-dotnet": [
        "actions/setup-node"
    ],
    "cycjimmy/semantic-release-action": [
        "actions/checkout",
        "actions/setup-node"
    ],
    "actions/dependency-review-action": [
        "actions/checkout"
    ],
}

# File patterns
WORKFLOW_FILE_EXTENSIONS = ['.yml', '.yaml']
TEMP_FILE_PREFIX = 'actchain_'

# Regular expressions
ACTION_REF_PATTERN = r'([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([a-zA-Z0-9_.-]+)'
USES_PATTERN = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([a-zA-Z0-9_.-]+)'
UNPINNED_ACTION_PATTERN = r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@v\d+'

# Scanner configuration
SCANNER_TYPES = ['zizmor', 'opengrep', 'all']
SCANNER_TIMEOUT = 300  # 5 minutes

# Report configuration
REPORT_VERSION = '1.0'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB