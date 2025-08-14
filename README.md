# ActChain - GitHub Actions Security Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

ActChain is a comprehensive security analysis tool for GitHub Actions workflows and their dependencies. It provides deep supply chain scanning capabilities to identify security vulnerabilities, misconfigurations, and compliance issues in your CI/CD pipelines.

## 🚀 Features

### Advanced Supply Chain Scanning
- **Deep Dependency Analysis**: Recursively analyze actions and their dependencies to any specified depth
- **Multi-Scanner Support**: Integrated support for Zizmor and OpenGrep/Semgrep scanners
- **Comprehensive Coverage**: Scan composite actions, reusable workflows, and Docker actions
- **Dependency Visualization**: Generate interactive dependency graphs to visualize your supply chain

### Security Analysis
- **Vulnerability Detection**: Identify security issues throughout the entire dependency chain
- **Configuration Assessment**: Detect misconfigurations and excessive permissions
- **Best Practice Validation**: Ensure adherence to GitHub Actions security best practices
- **Severity-Based Filtering**: Focus on issues that matter most with configurable severity levels

### Reporting & Visualization
- **Multi-Format Reports**: Generate both JSON and HTML reports for different use cases
- **Interactive HTML Reports**: Rich, searchable HTML reports with detailed findings
- **Dependency Graphs**: Visual representation of your action dependencies
- **Consolidated Analysis**: Single report combining findings from multiple scanners

## 📦 Installation


### Prerequisites
- Python 3.8 or higher
- Git
- GitHub personal access token

### Install ActChain
```bash
pip install actchain
```

### Install Optional Dependencies
For enhanced scanning capabilities:
```bash
# For OpenGrep/Semgrep scanning
pip install "actchain[all]"

# For dependency graph generation
sudo apt-get install graphviz  # Ubuntu/Debian
brew install graphviz          # macOS
```

## 🔧 Quick Start

### 1. Set up your GitHub token
```bash
export GITHUB_TOKEN="your_github_token_here"
```

### 2. Basic workflow scan
```bash
actchain scan --repo owner/repository
```

### 3. Advanced scanning with custom options
```bash
actchain scan \
  --repo owner/repository \
  --scanner all \
  --min-severity medium \
  --max-depth 10 \
  --dependency-graph \
  --output-dir ./reports
```

## 📋 Usage

### Command Line Interface

#### Scan Command
```bash
actchain scan [OPTIONS]
```

**Options:**
- `--repo, -r`: GitHub repository in "owner/repo" format (required)
- `--token, -t`: GitHub personal access token (or set GITHUB_TOKEN env var)
- `--workflow-path`: Path to specific workflow file to scan
- `--output-dir, -o`: Directory to save reports (default: ./actchain_reports)
- `--max-depth`: Maximum depth for dependency scanning (default: 5)
- `--scanner`: Scanner to use: zizmor, opengrep, or all (default: all)
- `--min-severity`: Minimum severity level: critical, high, medium, low (default: low)
- `--verbose, -v`: Enable verbose output
- `--debug, -d`: Enable debug mode with extensive logging
- `--deep-scan`: Enable comprehensive deep scanning
- `--dependency-graph`: Generate dependency graph visualization

#### Info Command
```bash
actchain info
```
Display system information and dependency status.

#### Setup Command
```bash
actchain setup [--install-all]
```
Set up ActChain and install optional dependencies.

#### Test Scanner Command
```bash
actchain test-scanner [zizmor|opengrep|all]
```
Test if specific scanners are working correctly.

### Configuration Examples

#### Basic Security Scan
```bash
actchain scan --repo myorg/myrepo
```

#### Comprehensive Security Audit
```bash
actchain scan \
  --repo myorg/myrepo \
  --scanner all \
  --min-severity high \
  --max-depth 15 \
  --dependency-graph \
  --verbose
```

#### Focused Critical Issues Scan
```bash
actchain scan \
  --repo myorg/myrepo \
  --min-severity critical \
  --scanner zizmor
```

#### Specific Workflow Analysis
```bash
actchain scan \
  --repo myorg/myrepo \
  --workflow-path .github/workflows/ci.yml \
  --max-depth 8
```

## 🔍 Scanning Capabilities

### Dependency Types Analyzed
- **Standard GitHub Actions**: Regular published actions from GitHub Marketplace
- **Composite Actions**: Actions that combine multiple steps or other actions
- **Reusable Workflows**: GitHub workflows called by other workflows
- **Local Actions**: Actions defined within the same repository
- **Docker Actions**: Actions that run within Docker containers

### Security Risks Detected
- **Unpinned Dependencies**: Actions not pinned to specific commit hashes
- **Excessive Permissions**: Actions requesting more permissions than necessary
- **Command Injection**: Potential command injection vulnerabilities
- **Code Injection**: Possible code injection points in scripts or inputs
- **Vulnerable Inputs**: Unsafe handling of inputs or environment variables
- **Transitive Vulnerabilities**: Security issues in nested dependencies
- **Configuration Issues**: Misconfigurations in workflow and action definitions

### Scanner Integration

#### Zizmor Scanner
- Specialized GitHub Actions security scanner
- Built-in rules for common vulnerabilities
- Fast and accurate analysis
- Default scanner for ActChain

#### OpenGrep/Semgrep Scanner
- Advanced static analysis capabilities
- Extensive rule sets for security patterns
- Custom rule support
- Comprehensive code analysis

## 📊 Report Formats

### JSON Reports
Structured data format suitable for:
- Integration with other tools
- Automated processing
- API consumption
- Custom analysis

### HTML Reports
Interactive web-based reports featuring:
- Searchable findings
- Severity-based filtering
- Detailed vulnerability descriptions
- Recommendations for remediation
- Visual severity indicators

### Dependency Graphs
Visual representations showing:
- Action dependency relationships
- Supply chain complexity
- Potential security bottlenecks
- Circular dependencies

## 🏗️ Project Structure

ActChain follows a modular architecture designed for maintainability and extensibility:

```
actchain/
├── README.md                    # Project documentation
├── LICENSE                      # MIT License
├── NOTICE                      # Third-party notices
├── requirements.txt             # Python dependencies  
├── setup.py                    # Package setup configuration
└── actchain/                   # Main package directory
    ├── __init__.py             # Package initialization
    ├── constants.py            # Constants and configuration
    ├── logging_config.py       # Logging configuration
    ├── cli/                    # Command-line interface
    │   ├── __init__.py
    │   ├── main.py             # Main CLI entry point
    │   ├── commands.py         # CLI command definitions
    │   └── display.py          # Display logic and UI
    ├── core/                   # Core functionality
    │   ├── __init__.py
    │   ├── github_client.py    # GitHub API client
    │   ├── workflow_parser.py  # Workflow parsing logic
    │   └── action_resolver.py  # Action resolution and dependency analysis
    ├── scanners/               # Security scanners
    │   ├── __init__.py
    │   ├── base.py             # Base scanner abstract class
    │   ├── zizmor.py          # Zizmor scanner implementation
    │   ├── opengrep.py        # OpenGrep scanner implementation
    │   └── factory.py         # Scanner factory and management
    ├── reports/                # Report generation
    │   ├── __init__.py
    │   ├── manager.py          # Report management
    │   └── html_converter.py   # JSON to HTML conversion
    └── utils/                  # Utility modules
        ├── __init__.py
        ├── file_utils.py       # File operations
        ├── path_utils.py       # Path utilities
        ├── system_utils.py     # System operations
        ├── format_utils.py     # Formatting utilities
        └── security_utils.py   # Security-related utilities
```

### Architecture Benefits

- **Modular Design**: Clear separation of concerns with logical module organization
- **Extensible Scanners**: Easy to add new security scanners through the factory pattern
- **Type Safety**: Comprehensive type hints throughout for better IDE support
- **Error Handling**: Robust error handling with custom exception classes
- **Security Focus**: Built-in security utilities and secure coding practices

## 🛡️ Security Best Practices

### Action Security
- **Pin to Commit Hashes**: Always use specific commit hashes instead of version tags
- **Minimal Permissions**: Use fine-grained permissions instead of `write-all`
- **Input Validation**: Validate and sanitize all action inputs
- **Secret Management**: Properly handle secrets and tokens
- **Regular Updates**: Keep dependencies updated while maintaining security

### Workflow Security
- **Least Privilege**: Apply principle of least privilege to all permissions
- **Environment Isolation**: Use appropriate environment protections
- **Artifact Security**: Secure artifact uploads and downloads
- **Branch Protection**: Implement proper branch protection rules
- **Review Process**: Establish code review processes for workflow changes

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup
```bash
git clone https://github.com/yourusername/actchain.git
cd actchain
pip install -e ".[dev]"
```

### Code Quality Standards
```bash
# Format code
black actchain/

# Lint code  
flake8 actchain/

# Type checking
mypy actchain/

# Run tests
pytest tests/ --cov=actchain
```

### Adding New Scanners
1. Create a new scanner class in `actchain/scanners/`
2. Inherit from `BaseScanner` 
3. Implement required methods
4. Register in the scanner factory
5. Add tests and documentation

### Contributing Guidelines
- Fork the repository and create a feature branch
- Follow the existing code style and conventions
- Add tests for new functionality
- Update documentation as needed
- Submit a pull request with a clear description

By contributing to ActChain, you agree that your contributions will be licensed under the MIT License.

## 📄 License

ActChain is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Dependencies

ActChain integrates with and depends on several third-party tools and libraries:

- **[Zizmor](https://github.com/woodruffw/zizmor)** - MIT License - GitHub Actions security scanner
- **[OpenGrep/Semgrep](https://github.com/opengrep/opengrep)** - LGPL-2.1 License - Static analysis tool
- **[PyGithub](https://github.com/PyGithub/PyGithub)** - LGPL-3.0 License - GitHub API library
- **[Rich](https://github.com/Textualize/rich)** - MIT License - Terminal formatting library
- **[Click](https://github.com/pallets/click)** - BSD-3-Clause License - Command line interface
- **[PyYAML](https://github.com/yaml/pyyaml)** - MIT License - YAML parser

See [NOTICE](NOTICE) file for complete third-party license information.

### Commercial Use

ActChain is freely available for commercial use under the MIT License. No restrictions apply beyond those specified in the license.

### Disclaimer

ActChain is an independent open source project and is not affiliated with or endorsed by GitHub, Inc., Trail of Bits, Semgrep, Inc., or any other third-party organizations whose tools or services may be integrated with or referenced by ActChain.

GitHub Actions is a trademark of GitHub, Inc.

## 🆘 Support

- **Documentation**: [Full documentation](https://actchain.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/actchain/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/actchain/discussions)
- **Security**: Report security vulnerabilities privately via email
- **Community**: Join our community discussions for help and feedback

## 🙏 Acknowledgments

- [Zizmor](https://github.com/woodruffw/zizmor) - GitHub Actions security scanner by Trail of Bits
- [Semgrep](https://semgrep.dev/) - Static analysis tool by Semgrep, Inc.
- [PyGithub](https://github.com/PyGithub/PyGithub) - GitHub API library
- [Rich](https://github.com/Textualize/rich) - Terminal formatting library
- [Click](https://github.com/pallets/click) - Command line interface framework

Special thanks to the security research community for their work on GitHub Actions security.

## 🚧 Roadmap

- [ ] Support for GitLab CI/CD pipelines
- [ ] Integration with popular CI/CD platforms
- [ ] Enhanced rule customization
- [ ] Performance optimizations
- [ ] Extended reporting formats
- [ ] Real-time monitoring capabilities
- [ ] IDE integrations and plugins
- [ ] Custom scanner plugin system
- [ ] SARIF format support
- [ ] Integration with security dashboards

## 📈 Performance & Scalability

ActChain is designed for efficiency:

- **Intelligent Caching**: Avoids redundant API calls and processing
- **Concurrent Scanning**: Parallel processing where possible
- **Memory Efficient**: Optimized for large dependency trees
- **Rate Limiting**: Respects GitHub API limits automatically
- **Incremental Updates**: Smart detection of changes


## Contributors

This project is made possible by the amazing people who have shaped it through their code, ideas, and guidance.  

- **[Igor Stepansky](https://github.com/iggypopi)** - *Lead & Primary Contributor*  
  Created the initial project setup, wrote all core features, and authored documentation.

- **[Avri Schneider](https://github.com/avri-schneider)**  
  Provided initial project code review, quality assurance, and deployment.

- **[Nissan Itzhakov](https://github.com/nissanitz)**  
  Deploying and maintenance of the project.

- **[Tomer Mekler](https://github.com/Ax-TomerMek)**  
  Advised on project direction, design, and planning.

- **[Sharon Ohayon](https://github.com/sharonOhayon)**  
  Project management and team leadership.

- **[Michael Goberman](https://github.com/micgob)**  
  Project management and team leadership.


---

**Made with ❤️ for the DevSecOps community**

*ActChain helps secure your software supply chain by providing comprehensive visibility into GitHub Actions workflows and their dependencies. Start securing your CI/CD pipelines today!*
