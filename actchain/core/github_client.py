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
GitHub API client for ActChain.
"""

import base64
import logging
from typing import Dict, List, Optional, Any
import yaml
from github import Github, GithubException

from ..constants import WORKFLOW_FILE_EXTENSIONS
from ..utils.security_utils import SecurityUtils

logger = logging.getLogger('actchain.core.github_client')


class GitHubClientError(Exception):
    """Custom exception for GitHub client errors."""
    pass


class GitHubClient:
    """GitHub API client for ActChain."""

    def __init__(self, token: str, repo_name: str):
        """
        Initialize the GitHub client.

        Args:
            token: GitHub personal access token
            repo_name: Repository name in the format "owner/repo"

        Raises:
            GitHubClientError: If client initialization fails
        """
        if not token:
            raise GitHubClientError("GitHub token is required")

        if not repo_name or '/' not in repo_name:
            raise GitHubClientError("Repository name must be in 'owner/repo' format")

        self.github = Github(token)
        self.repo_name = repo_name
        self.repo = None

        self._connect_to_repository()

    def _connect_to_repository(self) -> None:
        """
        Connect to the specified repository.

        Raises:
            GitHubClientError: If connection fails
        """
        try:
            logger.info(f"Connecting to repository {self.repo_name}")
            self.repo = self.github.get_repo(self.repo_name)

            # Test access by getting basic repo info
            _ = self.repo.name

            logger.info(f"Successfully connected to repository {self.repo_name}")
        except GithubException as e:
            error_msg = f"Could not access repository {self.repo_name}: {e.data.get('message', str(e))}"
            logger.error(error_msg)
            raise GitHubClientError(error_msg) from e

    def get_workflows(self) -> List[Dict[str, str]]:
        """
        Get all workflows in the repository.

        Returns:
            List of workflow dictionaries with name and path

        Raises:
            GitHubClientError: If unable to fetch workflows
        """
        workflows = []

        try:
            logger.info("Fetching workflow files from .github/workflows")
            contents = self.repo.get_contents(".github/workflows")

            for content in contents:
                if (content.type == "file" and
                        any(content.name.endswith(ext) for ext in WORKFLOW_FILE_EXTENSIONS)):
                    workflows.append({
                        "name": content.name,
                        "path": content.path
                    })

            logger.info(f"Found {len(workflows)} workflow files")
            return workflows

        except GithubException as e:
            if e.status == 404:
                logger.info("No .github/workflows directory found")
                return []
            else:
                error_msg = f"Error fetching workflows: {e.data.get('message', str(e))}"
                logger.error(error_msg)
                raise GitHubClientError(error_msg) from e

    def get_file_content(self, path: str) -> str:
        """
        Get the content of a file from the repository.

        Args:
            path: Path to the file in the repository

        Returns:
            Content of the file

        Raises:
            GitHubClientError: If unable to fetch file content
        """
        try:
            logger.info(f"Fetching file content: {path}")
            content = self.repo.get_contents(path)

            if isinstance(content, list):
                raise GitHubClientError(f"Path {path} points to a directory, not a file")

            decoded_content = base64.b64decode(content.content).decode('utf-8')
            logger.debug(f"Successfully fetched file: {path} ({len(decoded_content)} bytes)")
            return decoded_content

        except GithubException as e:
            error_msg = f"Could not get file content for {path}: {e.data.get('message', str(e))}"
            logger.error(SecurityUtils.sanitize_for_log(error_msg))
            raise GitHubClientError(error_msg) from e

    def get_file_content_optional(
            self,
            repo_name: str,
            path: str,
            ref: str = "main"
    ) -> Optional[str]:
        """
        Get the content of a file from any repository without raising exceptions.

        Args:
            repo_name: Repository name in the format "owner/repo"
            path: Path to the file in the repository
            ref: Git reference (branch, tag, commit)

        Returns:
            Content of the file, or None if not found
        """
        try:
            logger.debug(f"Attempting to fetch optional file: {repo_name}/{path}@{ref}")
            repo = self.github.get_repo(repo_name)
            content = repo.get_contents(path, ref=ref)

            if isinstance(content, list):
                logger.debug(f"Path {path} in {repo_name} points to a directory, not a file")
                return None

            decoded_content = base64.b64decode(content.content).decode('utf-8')
            logger.debug(f"Successfully fetched optional file: {repo_name}/{path} ({len(decoded_content)} bytes)")
            return decoded_content

        except GithubException as e:
            logger.debug(f"Could not get optional file {repo_name}/{path}: {e.data.get('message', str(e))}")
            return None
        except Exception as e:
            logger.debug(f"Error fetching optional file {repo_name}/{path}: {e}")
            return None

    def get_action_content(self, action_ref: str) -> Optional[Dict[str, Any]]:
        """
        Get the content of a GitHub Action.

        Args:
            action_ref: Action reference in the format "owner/repo@ref" or "owner/repo"

        Returns:
            Action data including content and metadata, or None if not found
        """
        if not action_ref:
            logger.warning("Empty action reference provided")
            return None

        # Parse the action reference
        ref_parts = self._parse_action_reference(action_ref)
        if not ref_parts:
            logger.warning(f"Invalid action reference format: {action_ref}")
            return None

        repo_name, ref = ref_parts

        try:
            logger.info(f"Fetching action repository: {repo_name}@{ref}")
            action_repo = self.github.get_repo(repo_name)

            # Try to get action.yml or action.yaml
            action_content = self._fetch_action_file(action_repo, ref)
            if not action_content:
                logger.warning(f"Could not find action file in {repo_name}")
                return None

            # Parse the action content
            try:
                action_data = yaml.safe_load(action_content)
            except yaml.YAMLError as e:
                logger.error(f"Invalid YAML in action {action_ref}: {e}")
                return None

            # Determine action type
            action_type = self._determine_action_type(action_data)

            logger.info(f"Successfully retrieved {action_type} action: {action_ref}")

            return {
                "ref": action_ref,
                "type": action_type,
                "content": action_data
            }

        except GithubException as e:
            logger.error(f"Error accessing repository {repo_name}: {e.data.get('message', str(e))}")
            return None

    def _parse_action_reference(self, action_ref: str) -> Optional[tuple]:
        """
        Parse an action reference into repo name and ref.

        Args:
            action_ref: Action reference string

        Returns:
            Tuple of (repo_name, ref) or None if invalid
        """
        if '@' in action_ref:
            parts = action_ref.split('@', 1)
            if len(parts) == 2 and '/' in parts[0]:
                return parts[0], parts[1]
        elif '/' in action_ref:
            return action_ref, "main"

        return None

    def _fetch_action_file(self, action_repo, ref: str) -> Optional[str]:
        """
        Fetch action.yml or action.yaml file from repository.

        Args:
            action_repo: GitHub repository object
            ref: Git reference

        Returns:
            Action file content or None if not found
        """
        action_files = ["action.yml", "action.yaml"]

        for filename in action_files:
            try:
                logger.debug(f"Trying to fetch {filename} from {action_repo.full_name}")
                action_file = action_repo.get_contents(filename, ref=ref)
                decoded_content = base64.b64decode(action_file.content).decode('utf-8')
                logger.debug(f"Found {filename} in {action_repo.full_name}")
                return decoded_content
            except GithubException:
                continue

        return None

    def _determine_action_type(self, action_data: Dict[str, Any]) -> str:
        """
        Determine the type of action based on its content.

        Args:
            action_data: Parsed action data

        Returns:
            Action type string
        """
        if not isinstance(action_data, dict):
            return "unknown"

        runs_config = action_data.get('runs', {})
        if not isinstance(runs_config, dict):
            return "unknown"

        using = runs_config.get('using', 'unknown')

        # Map the 'using' field to action types
        type_mapping = {
            'composite': 'composite',
            'docker': 'docker',
            'node12': 'javascript',
            'node16': 'javascript',
            'node20': 'javascript',
        }

        return type_mapping.get(using, using)