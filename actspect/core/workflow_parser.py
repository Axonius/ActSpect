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
Parser for GitHub Actions workflow files.
"""

import logging
from typing import Dict, Set, Any
import yaml
from yaml.parser import ParserError
from yaml.scanner import ScannerError

logger = logging.getLogger('actspect.core.workflow_parser')


class WorkflowParseError(Exception):
    """Custom exception for workflow parsing errors."""
    pass


class WorkflowParser:
    """Parser for GitHub Actions workflow files."""

    def __init__(self):
        """Initialize the workflow parser."""
        self.logger = logger

    def parse(self, content: str) -> Dict[str, Any]:
        """
        Parse the content of a workflow file.

        Args:
            content: Content of the workflow file

        Returns:
            Parsed workflow data

        Raises:
            WorkflowParseError: If parsing fails
        """
        if not content or not content.strip():
            raise WorkflowParseError("Workflow content is empty")

        try:
            self.logger.info("Parsing workflow file")
            workflow_data = yaml.safe_load(content)

            if not isinstance(workflow_data, dict):
                raise WorkflowParseError("Workflow must be a YAML dictionary")

            # Log the structure for debugging
            self.logger.debug(f"Parsed workflow with keys: {list(workflow_data.keys())}")

            # Validate basic structure with better error messages
            self._validate_workflow_structure(workflow_data, content)

            self.logger.debug(
                f"Successfully parsed workflow with {len(workflow_data.keys())} root keys"
            )
            return workflow_data

        except (ParserError, ScannerError) as e:
            error_msg = f"Failed to parse workflow YAML: {e}"
            self.logger.error(error_msg)
            raise WorkflowParseError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error parsing workflow: {e}"
            self.logger.error(error_msg)
            raise WorkflowParseError(error_msg) from e

    def extract_actions(self, workflow_data: Dict[str, Any]) -> Set[str]:
        """
        Extract all action references from a workflow.

        Args:
            workflow_data: Parsed workflow data

        Returns:
            Set of action references
        """
        if not isinstance(workflow_data, dict):
            self.logger.warning("Invalid workflow data provided")
            return set()

        actions = set()
        jobs = workflow_data.get('jobs', {})

        if not jobs:
            self.logger.info("No jobs found in workflow")
            return actions

        self.logger.info(f"Extracting actions from {len(jobs)} jobs")

        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                self.logger.warning(f"Invalid job data for job '{job_id}'")
                continue

            job_actions = self._extract_actions_from_job(job_id, job_data)
            actions.update(job_actions)

        self.logger.info(f"Found {len(actions)} action references in workflow")
        return actions

    def extract_composite_actions(self, action_data: Dict[str, Any]) -> Set[str]:
        """
        Extract actions from a composite action.

        Args:
            action_data: Parsed action data

        Returns:
            Set of action references
        """
        actions = set()

        if not isinstance(action_data, dict):
            self.logger.debug("Invalid action data provided")
            return actions

        # Check if this is a composite action
        runs_config = action_data.get('runs', {})
        if not isinstance(runs_config, dict):
            return actions

        if runs_config.get('using') != 'composite':
            self.logger.debug("Not a composite action")
            return actions

        self.logger.info("Extracting actions from composite action")
        steps = runs_config.get('steps', [])

        if not isinstance(steps, list):
            self.logger.warning("Invalid steps format in composite action")
            return actions

        self.logger.debug(f"Found {len(steps)} steps in composite action")

        for step in steps:
            if isinstance(step, dict) and 'uses' in step:
                action_ref = step['uses']
                if isinstance(action_ref, str) and self._is_valid_action_ref(action_ref):
                    self.logger.debug(f"Found nested action in composite: {action_ref}")
                    actions.add(action_ref)

        self.logger.info(f"Found {len(actions)} actions in composite action")
        return actions

    def get_workflow_metadata(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract metadata from a workflow.

        Args:
            workflow_data: Parsed workflow data

        Returns:
            Workflow metadata
        """
        if not isinstance(workflow_data, dict):
            return {}

        metadata = {
            "name": workflow_data.get("name", "Unnamed workflow"),
            "on": workflow_data.get("on", {}),
            "permissions": workflow_data.get("permissions", {})
        }

        # Count jobs and steps
        jobs = workflow_data.get("jobs", {})
        metadata["jobs_count"] = len(jobs) if isinstance(jobs, dict) else 0

        steps_count = 0
        if isinstance(jobs, dict):
            for job_data in jobs.values():
                if isinstance(job_data, dict):
                    steps = job_data.get("steps", [])
                    if isinstance(steps, list):
                        steps_count += len(steps)

        metadata["steps_count"] = steps_count

        self.logger.debug(f"Workflow metadata: {metadata}")
        return metadata

    def analyze_permissions(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the permissions used in a workflow.

        Args:
            workflow_data: Parsed workflow data

        Returns:
            Permissions analysis
        """
        if not isinstance(workflow_data, dict):
            return {}

        # Get top-level permissions
        top_level_permissions = workflow_data.get("permissions", {})

        # Check for wildcard permissions
        has_wildcard_permissions = self._has_wildcard_permissions(top_level_permissions)

        # Get job-level permissions
        job_permissions = {}
        jobs = workflow_data.get("jobs", {})

        if isinstance(jobs, dict):
            for job_id, job_data in jobs.items():
                if isinstance(job_data, dict) and "permissions" in job_data:
                    job_permissions[job_id] = job_data["permissions"]
                    if self._has_wildcard_permissions(job_data["permissions"]):
                        has_wildcard_permissions = True

        return {
            "top_level_permissions": top_level_permissions,
            "job_permissions": job_permissions,
            "has_wildcard_permissions": has_wildcard_permissions
        }

    def _validate_workflow_structure(self, workflow_data: Dict[str, Any], original_content: str = "") -> None:
        """
        Validate basic workflow structure with improved error messages.

        Args:
            workflow_data: Parsed workflow data
            original_content: Original workflow content for debugging

        Raises:
            WorkflowParseError: If structure is invalid
        """
        # Check for 'on' trigger with better debugging
        # GitHub Actions supports various trigger formats:
        # on: push, on: true, on: false, etc.
        trigger_keys = ['on', True, False]  # YAML may parse 'on: true' as {True: true}
        has_trigger = any(key in workflow_data for key in trigger_keys)

        if not has_trigger:
            # Provide detailed debugging information
            available_keys = list(workflow_data.keys())
            self.logger.error(f"Workflow validation failed. Available keys: {available_keys}")

            # Log first few lines of content for debugging
            content_preview = '\n'.join(original_content.split('\n')[:10])
            self.logger.debug(f"Workflow content preview:\n{content_preview}")

            raise WorkflowParseError(
                f"Workflow must have a trigger ('on' field). "
                f"Found keys: {available_keys}. "
                f"This might be a workflow template, composite action, or malformed workflow file."
            )

        # Log that we found a trigger for debugging
        found_triggers = [key for key in trigger_keys if key in workflow_data]
        self.logger.debug(f"Found workflow triggers: {found_triggers}")

        if 'jobs' not in workflow_data:
            available_keys = list(workflow_data.keys())
            raise WorkflowParseError(
                f"Workflow must have 'jobs'. Found keys: {available_keys}. "
                f"This might be a reusable workflow or action definition."
            )

        jobs = workflow_data.get('jobs')
        if not isinstance(jobs, dict):
            raise WorkflowParseError(
                f"Workflow 'jobs' must be a dictionary, got {type(jobs).__name__}"
            )

        if not jobs:
            raise WorkflowParseError("Workflow must have at least one job")

    def _extract_actions_from_job(self, job_id: str, job_data: Dict[str, Any]) -> Set[str]:
        """Extract actions from a single job."""
        actions = set()
        steps = job_data.get('steps', [])

        if not isinstance(steps, list):
            self.logger.warning(f"Invalid steps format in job '{job_id}'")
            return actions

        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                self.logger.warning(f"Invalid step format in job '{job_id}', step {step_idx}")
                continue

            if 'uses' in step:
                action_ref = step['uses']
                if isinstance(action_ref, str) and self._is_valid_action_ref(action_ref):
                    self.logger.debug(f"Found action reference: {action_ref}")
                    actions.add(action_ref)

        return actions

    def _is_valid_action_ref(self, action_ref: str) -> bool:
        """
        Check if an action reference is valid.

        Args:
            action_ref: Action reference to validate

        Returns:
            True if valid, False otherwise
        """
        if not action_ref or not isinstance(action_ref, str):
            return False

        # Allow Docker actions
        if action_ref.startswith('docker://'):
            return True

        # Allow local actions (though we typically don't scan these deeply)
        if action_ref.startswith('./'):
            return True

        # Check for GitHub action format (owner/repo@version or owner/repo)
        if '/' in action_ref and not action_ref.startswith('/'):
            return True

        return False

    def _has_wildcard_permissions(self, permissions: Any) -> bool:
        """
        Check if permissions include wildcard access.

        Args:
            permissions: Permissions configuration

        Returns:
            True if wildcard permissions are found
        """
        if isinstance(permissions, str):
            return permissions in ["write-all", "read-all"]

        if isinstance(permissions, dict):
            return any(
                value in ["write", "write-all", "read-all"]
                for value in permissions.values()
                if isinstance(value, str)
            )

        return False
