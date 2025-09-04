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

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="actspect",
    version="0.1.0",
    author="Axonius Solutions Ltd.",
    author_email="github@axonius.com",
    description="A comprehensive security analysis tool for GitHub Actions workflows and their dependencies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Axonius/ActSpect",
    project_urls={
        "Bug Tracker": "https://github.com/Axonius/ActSpect/issues",
        "Documentation": "https://github.com/Axonius/ActSpect/blob/main/Documentation.md",
        "Source Code": "https://github.com/Axonius/ActSpect",
        "License": "https://github.com/Axonius/ActSpect/blob/main/LICENSE",
        "Releases": "https://github.com/Axonius/ActSpect/releases",
        "Changelog": "https://github.com/Axonius/ActSpect/blob/main/CHANGELOG.md",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    keywords="github-actions security scanning workflow ci-cd devops supply-chain vulnerability analysis open-source",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "PyGithub>=1.55",
        "pyyaml>=6.0",
        "click>=8.0.0",
        "rich>=10.0.0",
        "requests>=2.25.0",
        "zizmor>=1.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.910",
            "pre-commit>=2.15",
            "twine>=4.0",
            "build>=0.7",
        ],
        "docs": [
            "mkdocs>=1.4",
            "mkdocs-material>=8.0",
            "mkdocstrings[python]>=0.19",
        ],
        "all": [
            # Note: OpenGrep must be installed separately as it's not available via pip
            # Users should install it from: https://github.com/opengrep/opengrep/releases
            # Graphviz system package is also required for dependency graphs (installed via system package manager)
        ],
    },
    entry_points={
        'console_scripts': [
            'actspect=actspect.cli.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        "actspect": ["py.typed"],
    },
    zip_safe=False,
    license="MIT",
    license_files=["LICENSE", "NOTICE"],
    platforms=["any"],
)
