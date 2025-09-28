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
Resolver for GitHub Actions, handling references and composite actions.
"""

import re
import logging
from typing import Dict, Set, Any, Optional, TYPE_CHECKING

from ..constants import ACTION_REF_PATTERN, USES_PATTERN

if TYPE_CHECKING:
    from .github_client import GitHubClient
    from .workflow_parser import WorkflowParser

logger = logging.getLogger('actspect.core.action_resolver')


class ActionResolver:
    """Resolves GitHub Actions and analyzes their dependencies."""

    def __init__(self, github_client: 'GitHubClient'):
        """
        Initialize the action resolver.

        Args:
            github_client: GitHub client instance
        """
        self.github_client = github_client
        self.action_cache: Dict[str, Any] = {}

    def resolve_action(self, action_ref: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a GitHub Action reference to its content.

        Args:
            action_ref: Action reference in the format "owner/repo@ref" or "owner/repo"

        Returns:
            Action data including content and metadata, or None if resolution fails
        """
        if not action_ref:
            logger.warning("Empty action reference provided")
            return None

        # Check cache first
        if action_ref in self.action_cache:
            logger.debug(f"Cache hit for {action_ref}")
            return self.action_cache[action_ref]

        logger.info(f"Resolving action: {action_ref}")

        # Handle Docker actions
        if action_ref.startswith('docker://'):
            action_data = self._create_docker_action_data(action_ref)
            self.action_cache[action_ref] = action_data
            return action_data

        # Handle local actions (skip for now)
        if action_ref.startswith('./'):
            logger.debug(f"Skipping local action: {action_ref}")
            action_data = self._create_local_action_data(action_ref)
            self.action_cache[action_ref] = action_data
            return action_data

        # Ensure action reference has a version
        normalized_ref = self._normalize_action_reference(action_ref)

        # Resolve using GitHub client
        logger.info(f"Fetching action content for {normalized_ref}")
        action_data = self.github_client.get_action_content(normalized_ref)

        if action_data:
            logger.info(f"Successfully resolved {normalized_ref}")
        else:
            logger.warning(f"Failed to resolve {normalized_ref}")

        # Cache the result (including None results to avoid repeated failures)
        self.action_cache[action_ref] = action_data
        return action_data

    def get_action_dependencies(
            self,
            action_data: Dict[str, Any],
            workflow_parser: 'WorkflowParser'
    ) -> Set[str]:
        """
        Get the dependencies of an action.

        Args:
            action_data: Action data
            workflow_parser: Workflow parser instance

        Returns:
            Set of action references
        """
        if not action_data or 'content' not in action_data:
            logger.debug("No content available to extract dependencies")
            return set()

        dependencies = set()
        action_ref = action_data.get('ref', 'unknown')
        action_type = action_data.get('type', '')
        content = action_data.get('content', {})

        # Extract dependencies from different sources
        dependencies.update(self._extract_composite_dependencies(action_type, content))
        dependencies.update(self._extract_uses_dependencies(content))

        # Remove self-references
        dependencies.discard(action_ref)

        if dependencies:
            logger.info(f"Found {len(dependencies)} dependencies for {action_ref}")
            logger.debug(f"Dependencies for {action_ref}: {dependencies}")
        else:
            logger.debug(f"No dependencies found in action {action_ref}")

        return dependencies

    def analyze_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an action for metadata and potential security issues.

        Args:
            action_data: Action data

        Returns:
            Action analysis
        """
        if not action_data or 'content' not in action_data:
            return {
                "ref": action_data.get("ref", "unknown") if action_data else "unknown",
                "type": "unknown",
                "error": "No content available for analysis"
            }

        content = action_data['content']
        action_ref = action_data.get("ref", "unknown")

        # Basic metadata
        analysis = {
            "ref": action_ref,
            "type": action_data.get("type", "unknown"),
            "name": content.get("name", "Unnamed action"),
            "description": content.get("description", ""),
            "author": content.get("author", "")
        }

        # Execution metadata
        runs_config = content.get("runs", {})
        analysis["execution_type"] = runs_config.get("using", "unknown")

        # Permissions analysis
        analysis["permissions"] = content.get("permissions", {})

        # Security warnings
        analysis["warnings"] = self._analyze_security_issues(content, action_ref)

        return analysis

    def _create_docker_action_data(self, action_ref: str) -> Dict[str, Any]:
        """Create action data for Docker actions."""
        logger.debug(f"{action_ref} is a Docker action")
        return {
            "ref": action_ref,
            "type": "docker",
            "content": {
                "runs": {
                    "using": "docker",
                    "image": action_ref.replace('docker://', '')
                }
            }
        }

    def _create_local_action_data(self, action_ref: str) -> Dict[str, Any]:
        """Create action data for local actions."""
        logger.debug(f"{action_ref} is a local action")
        return {
            "ref": action_ref,
            "type": "local",
            "content": {
                "runs": {
                    "using": "local"
                }
            }
        }

    def _normalize_action_reference(self, action_ref: str) -> str:
        """Normalize action reference by adding default version if missing."""
        if '@' not in action_ref:
            logger.debug(f"{action_ref} does not specify a version, using main")
            return f"{action_ref}@main"
        return action_ref

    def _extract_composite_dependencies(self, action_type: str, content: Dict[str, Any]) -> Set[str]:
        """Extract dependencies from composite action steps."""
        dependencies = set()

        if action_type == 'composite':
            logger.debug("Extracting dependencies from composite action")
            runs_config = content.get('runs', {})
            steps = runs_config.get('steps', [])

            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict) and 'uses' in step:
                        action_uses = step['uses']
                        if isinstance(action_uses, str) and not action_uses.startswith('./'):
                            logger.debug(f"Found dependency in composite action: {action_uses}")
                            dependencies.add(action_uses)

        return dependencies

    def _extract_uses_dependencies(self, content: Dict[str, Any]) -> Set[str]:
        """Recursively extract 'uses' fields from action content."""
        return self._extract_uses_from_dict(content)

    def _extract_uses_from_dict(self, content_dict: Any, prefix: str = '') -> Set[str]:
        """
        Recursively extract 'uses' fields from a nested dictionary.

        Args:
            content_dict: Dictionary to extract from
            prefix: Current key prefix for logging

        Returns:
            Set of action references
        """
        if not isinstance(content_dict, dict):
            return set()

        uses_refs = set()

        for key, value in content_dict.items():
            current_path = f"{prefix}.{key}" if prefix else key

            if (key == 'uses' and isinstance(value, str) and
                    '/' in value and not value.startswith('./')):
                uses_refs.add(value)
                logger.debug(f"Found 'uses' at {current_path}: {value}")

            # Check nested dictionaries
            elif isinstance(value, dict):
                nested_refs = self._extract_uses_from_dict(value, current_path)
                uses_refs.update(nested_refs)

            # Check lists of dictionaries
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_path = f"{current_path}[{i}]"
                        nested_refs = self._extract_uses_from_dict(item, item_path)
                        uses_refs.update(nested_refs)

        return uses_refs

    def _get_base_ref(self, action_ref: str) -> str:
        """Get the base reference (owner/repo) without version."""
        if '@' in action_ref:
            return action_ref.split('@')[0]
        return action_ref

    def _analyze_security_issues(self, content: Dict[str, Any], action_ref: str) -> list:
        """Analyze action content for potential security issues."""
        warnings = []

        # Check for token inputs
        inputs = content.get("inputs", {})
        if isinstance(inputs, dict):
            for input_name, input_data in inputs.items():
                if not isinstance(input_data, dict):
                    continue

                # Check for token-related input names
                if input_name.lower() in ["token", "github_token", "pat", "access_token"]:
                    warnings.append(f"Action requests a token input named '{input_name}'")

                # Check for suspicious default values
                default = input_data.get("default", "")
                if isinstance(default, str) and any(s in default for s in ["${{", "$(", "`"]):
                    warnings.append(f"Input '{input_name}' has a default value with substitution")

        # Check Docker image security
        runs_config = content.get("runs", {})
        if isinstance(runs_config, dict) and runs_config.get("using") == "docker":
            image = runs_config.get("image", "")
            if isinstance(image, str):
                if ":" not in image or image.split(":")[1] in ["latest", "master", "main"]:
                    warnings.append("Docker image uses floating tag (latest/master/main)")

        return warnings
