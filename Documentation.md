# ActSpect - Complete Project Documentation

*Last Updated: December 2024*

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Overview](#architecture-overview)
3. [Project Structure](#project-structure)
4. [Core Concepts](#core-concepts)
5. [Module Documentation](#module-documentation)
6. [Development Guide](#development-guide)
7. [Configuration and Settings](#configuration-and-settings)
8. [Troubleshooting](#troubleshooting)
9. [Extension Guide](#extension-guide)

## 📖 Project Overview

### What is ActSpect?

ActSpect is a comprehensive security analysis tool for GitHub Actions workflows and their dependencies. It performs deep supply chain scanning to identify security vulnerabilities, misconfigurations, and compliance issues in CI/CD pipelines.

### Key Features

- **Deep Dependency Analysis**: Recursively scans GitHub Actions and their dependencies
- **Multi-Scanner Support**: Integrates Zizmor and OpenGrep/Semgrep scanners
- **Supply Chain Visualization**: Generates dependency graphs and trees
- **Multi-Format Reporting**: JSON and HTML reports with detailed findings
- **Configurable Scanning**: Adjustable depth, severity filtering, and scanner selection

### Design Philosophy

1. **Modular Architecture**: Clear separation of concerns across modules
2. **Extensibility**: Easy to add new scanners, report formats, and features
3. **Security First**: Built-in security practices and safe handling of sensitive data
4. **User Experience**: Rich CLI with helpful error messages and progress tracking
5. **Type Safety**: Comprehensive type hints for better maintainability

## 🏗️ Architecture Overview

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Layer     │    │  Core Business  │    │    External     │
│                 │    │     Logic       │    │   Dependencies  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Commands      │───▶│ • GitHub Client │───▶│ • GitHub API    │
│ • Display       │    │ • Workflow Parser│   │ • Zizmor        │
│ • User Input    │    │ • Action Resolver│   │ • OpenGrep      │
└─────────────────┘    │ • Scanners      │    │ • Graphviz      │
                       │ • Reports       │    └─────────────────┘
                       └─────────────────┘
```

### Data Flow

1. **Input**: User specifies repository and scanning options
2. **Authentication**: GitHub client authenticates with provided token
3. **Workflow Discovery**: Fetches and lists available workflows
4. **Workflow Parsing**: Parses selected workflow YAML structure
5. **Action Extraction**: Identifies all GitHub Actions used
6. **Dependency Resolution**: Recursively resolves action dependencies
7. **Security Scanning**: Runs configured scanners on each component
8. **Report Generation**: Consolidates findings into reports
9. **Output**: Displays results and saves reports to disk

## 📁 Project Structure

### Root Level Files

```
ActSpect/
├── .gitignore                 # Git ignore patterns
├── README.md                  # User-facing documentation
├── PROJECT_DOCUMENTATION.md  # This comprehensive guide
├── requirements.txt           # Python dependencies
└── setup.py                   # Package configuration and metadata
```

### Main Package Structure

```
actspect/
├── __init__.py               # Package initialization and main exports
├── constants.py              # Project-wide constants and configuration
├── logging_config.py         # Logging setup and configuration
├── cli/                      # Command-line interface
├── core/                     # Core business logic
├── scanners/                 # Security scanners
├── reports/                  # Report generation
└── utils/                    # Utility functions
```

## 🧠 Core Concepts

### 1. Workflow Scanning Process

**Workflow**: A GitHub Actions YAML file that defines CI/CD automation
**Action**: A reusable unit of code that performs a specific task
**Dependency**: An action that another action depends on (directly or transitively)
**Supply Chain**: The complete tree of all actions and their dependencies

### 2. Dependency Resolution

ActSpect builds a dependency tree by:
1. Parsing workflow files to extract action references
2. Fetching action definitions from GitHub
3. Analyzing composite actions for nested dependencies
4. Recursively following the dependency chain
5. Detecting circular dependencies and handling edge cases

### 3. Security Scanning

Multiple scanners analyze different aspects:
- **Static Analysis**: Code patterns and configurations
- **Permission Analysis**: Excessive or unnecessary permissions
- **Dependency Security**: Known vulnerabilities in dependencies
- **Best Practices**: Adherence to security guidelines

### 4. Report Generation

Results are consolidated into:
- **JSON Reports**: Machine-readable structured data
- **HTML Reports**: Human-readable interactive reports
- **Dependency Graphs**: Visual representations of the supply chain

## 📚 Module Documentation

### CLI Module (`actspect/cli/`)

**Purpose**: Handles all user interaction and command-line interface

#### `cli/main.py`
- **Function**: Main entry point for the CLI application
- **Key Features**: 
  - ASCII logo display
  - Dependency checking
  - Error handling and graceful exit
- **Entry Point**: Called when user runs `actspect` command

#### `cli/commands.py`
- **Function**: Defines CLI commands and their parameters
- **Key Commands**:
  - `scan`: Main scanning command with all options
  - `info`: Environment and dependency information
- **Validation**: Input validation and user guidance

#### `cli/display.py`
- **Function**: All UI display logic and scanning orchestration
- **Key Features**:
  - Progress tracking with Rich library
  - Interactive workflow selection
  - Error display with helpful suggestions
  - Results presentation and formatting
- **Integration**: Coordinates between all other modules

### Core Module (`actspect/core/`)

**Purpose**: Core business logic and GitHub API interaction

#### `core/github_client.py`
- **Function**: GitHub API client for fetching workflows and actions
- **Key Features**:
  - Authentication handling
  - Rate limiting awareness
  - Caching for performance
  - Error handling with retry logic
- **Security**: Safe token handling and log sanitization

#### `core/workflow_parser.py`
- **Function**: Parses GitHub Actions YAML workflows
- **Key Features**:
  - YAML parsing and validation
  - Action reference extraction
  - Composite action support
  - Permission analysis
- **Error Handling**: Detailed error messages for malformed workflows

#### `core/action_resolver.py`
- **Function**: Resolves action references and builds dependency trees
- **Key Features**:
  - Action content fetching
  - Dependency extraction from multiple sources
  - Caching for performance
  - Security analysis of action configurations
- **Intelligence**: Known dependency patterns for popular actions

### Scanners Module (`actspect/scanners/`)

**Purpose**: Security scanner implementations and management

#### `scanners/base.py`
- **Function**: Abstract base class defining scanner interface
- **Key Features**:
  - Common scanner functionality
  - Severity filtering
  - Report structure standardization
- **Design Pattern**: Template method pattern for consistent behavior

#### `scanners/zizmor.py`
- **Function**: Zizmor scanner implementation
- **Key Features**:
  - GitHub Actions specific security rules
  - Fast and accurate scanning
  - Automatic installation if missing
- **Output Parsing**: Converts Zizmor output to standardized format

#### `scanners/opengrep.py`
- **Function**: OpenGrep/Semgrep scanner implementation
- **Key Features**:
  - Advanced static analysis
  - Extensive rule sets
  - Fallback pattern matching
- **Integration**: Uses built-in GitHub Actions rule sets

#### `scanners/factory.py`
- **Function**: Scanner factory and management
- **Key Features**:
  - Scanner instantiation
  - Error handling for missing scanners
  - Support for multiple scanner execution
- **Extensibility**: Easy addition of new scanners

### Reports Module (`actspect/reports/`)

**Purpose**: Report generation and output formatting

#### `reports/manager.py`
- **Function**: Manages report generation and storage
- **Key Features**:
  - Unique scan directory creation
  - Consolidated report generation
  - Dependency graph generation
  - Statistics aggregation
- **Organization**: Creates timestamped scan directories

#### `reports/html_converter.py`
- **Function**: Converts JSON reports to interactive HTML
- **Key Features**:
  - Rich HTML formatting with CSS
  - Severity-based color coding
  - Searchable and filterable content
  - Responsive design
- **Styling**: Professional appearance with modern CSS

### Utils Module (`actspect/utils/`)

**Purpose**: Utility functions organized by concern

#### `utils/path_utils.py`
- **Function**: Path operations and validation
- **Key Features**: Path normalization, directory creation, filename sanitization

#### `utils/file_utils.py`
- **Function**: Safe file operations
- **Key Features**: Secure read/write operations, error handling, encoding management

#### `utils/system_utils.py`
- **Function**: System operations and environment detection
- **Key Features**: Command availability checking, platform info, dependency validation

#### `utils/format_utils.py`
- **Function**: Data formatting utilities
- **Key Features**: Human-readable duration and file size formatting

#### `utils/security_utils.py`
- **Function**: Security-related utilities
- **Key Features**: Secure temporary files, log sanitization, secret detection

## 🛠️ Development Guide

### Setting Up Development Environment

1. **Clone and Setup**:
   ```bash
   git clone <repository-url>
   cd ActSpect
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -e ".[dev]"
   ```

2. **Environment Variables**:
   ```bash
   export GITHUB_TOKEN="your_github_token_here"
   export ACTSPECT_LOG_LEVEL="DEBUG"  # Optional: for development
   ```

### Code Quality Standards

- **Type Hints**: All functions must have comprehensive type hints
- **Docstrings**: All public functions must have detailed docstrings
- **Error Handling**: Use custom exception classes for different error types
- **Logging**: Use appropriate log levels and sanitize sensitive information
- **Testing**: Write tests for new functionality (when test suite is added)

### Adding New Features

#### Adding a New Scanner

1. **Create Scanner Class** (`actspect/scanners/new_scanner.py`):
   ```python
   from .base import BaseScanner
   
   class NewScanner(BaseScanner):
       def __init__(self, min_severity: str = "low"):
           super().__init__(min_severity)
           self.scanner_name = "New Scanner"
       
       def scan_workflow(self, content: str, path: str) -> Dict[str, Any]:
           # Implementation here
           pass
       
       def scan_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
           # Implementation here
           pass
   ```

2. **Register in Factory** (`actspect/scanners/factory.py`):
   ```python
   from .new_scanner import NewScanner
   
   # Add to create_scanner method
   elif scanner_type == "newscanner":
       return NewScanner(min_severity)
   ```

3. **Update Constants** (`actspect/constants.py`):
   ```python
   SCANNER_TYPES = ['zizmor', 'opengrep', 'newscanner', 'all']
   ```

#### Adding a New Report Format

1. **Create Converter** (`actspect/reports/new_format_converter.py`):
   ```python
   def convert_json_to_new_format(json_path: str) -> Optional[str]:
       # Implementation here
       pass
   ```

2. **Integrate in Manager** (`actspect/reports/manager.py`):
   ```python
   # Add to report generation logic
   if config.get('new_format'):
       new_format_path = convert_json_to_new_format(consolidated_path)
   ```

### Testing Strategy

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete scanning workflows
- **Security Tests**: Verify secure handling of sensitive data

### Performance Considerations

- **Caching**: Implement caching for expensive operations (GitHub API calls)
- **Concurrency**: Consider async operations for I/O-bound tasks
- **Memory Management**: Handle large dependency trees efficiently
- **Rate Limiting**: Respect GitHub API rate limits

## ⚙️ Configuration and Settings

### Environment Variables

- `GITHUB_TOKEN`: Required for GitHub API access
- `ACTSPECT_LOG_LEVEL`: Optional logging level (DEBUG, INFO, WARNING, ERROR)
- `ACTSPECT_OUTPUT_DIR`: Optional default output directory

### Configuration Files

ActSpect currently uses command-line arguments for configuration. Future versions might support:
- `~/.actspect/config.yaml`: User-level configuration
- `.actspect.yaml`: Project-level configuration

### Default Settings

```python
# From actspect/constants.py
DEFAULT_MAX_DEPTH = 5          # Maximum dependency depth
DEFAULT_MIN_SEVERITY = 'low'   # Minimum severity to report
DEFAULT_OUTPUT_DIR = './actspect_reports'  # Default output location
SCANNER_TIMEOUT = 300          # Scanner timeout in seconds
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "Workflow must have an 'on' trigger"
**Cause**: File is not a complete GitHub Actions workflow
**Solution**: Verify the file has `on:` and `jobs:` sections, might be a template or composite action

#### 2. "Scanner not found" 
**Cause**: Scanner dependencies not installed
**Solution**: Install scanner manually or use `pip install "actspect[all]"`

#### 3. "Rate limit exceeded"
**Cause**: Too many GitHub API requests
**Solution**: Wait for rate limit reset or use authenticated token with higher limits

#### 4. "Permission denied"
**Cause**: Invalid or insufficient GitHub token permissions
**Solution**: Ensure token has `repo` scope and repository access

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
actspect scan --repo owner/repo --debug
```

This provides:
- Detailed logging to file
- Step-by-step execution traces
- API request/response information
- Error stack traces

### Log Files

- **Console Logs**: Real-time progress and errors
- **Debug Logs**: `{output_dir}/actspect_debug.log` (when --debug is used)
- **Scanner Logs**: Individual scanner outputs in scan directories

## 🚀 Extension Guide

### Architecture Principles for Extensions

1. **Single Responsibility**: Each module should have one clear purpose
2. **Open/Closed Principle**: Open for extension, closed for modification
3. **Dependency Injection**: Pass dependencies rather than creating them
4. **Interface Segregation**: Use specific interfaces rather than large ones
5. **Composition over Inheritance**: Prefer composition for flexibility

### Extension Points

#### 1. New Scanner Types
- Implement `BaseScanner` interface
- Add to factory pattern
- Update constants and CLI options

#### 2. New Report Formats
- Create converter functions
- Integrate with report manager
- Add CLI options for new formats

#### 3. New Data Sources
- Extend GitHub client or create new clients
- Implement standard data interfaces
- Add authentication mechanisms

#### 4. New Analysis Types
- Create analysis modules in core/
- Integrate with action resolver
- Add configuration options

### Best Practices for Extensions

- **Error Handling**: Use specific exception types
- **Logging**: Use appropriate log levels and modules
- **Configuration**: Use constants file for settings
- **Documentation**: Document all new functionality
- **Testing**: Write comprehensive tests
- **Backward Compatibility**: Maintain existing interfaces

### Future Enhancement Ideas

1. **Additional Scanners**: CodeQL, Snyk, custom rules
2. **More Report Formats**: PDF, XML, SARIF
3. **Real-time Monitoring**: Webhook-based scanning
4. **IDE Integrations**: VS Code extension, GitHub App
5. **Database Storage**: Persistent storage for scan history
6. **API Interface**: REST API for programmatic access
7. **Custom Rules**: User-defined security rules
8. **Team Features**: Multi-user environments, role-based access

---

## 📝 Quick Reference

### Key Files to Remember

- **Entry Point**: `actspect/cli/main.py`
- **Main Logic**: `actspect/cli/display.py`
- **Configuration**: `actspect/constants.py`
- **GitHub API**: `actspect/core/github_client.py`
- **Scanning**: `actspect/scanners/factory.py`
- **Reports**: `actspect/reports/manager.py`

### Common Development Tasks

- **Add Scanner**: Modify `scanners/` directory
- **Change CLI**: Modify `cli/commands.py`
- **Update Constants**: Edit `constants.py`
- **Fix Bug**: Check relevant module in organized structure
- **Add Tests**: Create in `tests/` directory (when added)

### Important Concepts

- **Dependency Tree**: Hierarchical structure of action dependencies
- **Supply Chain**: Complete set of actions and their relationships
- **Composite Actions**: Actions that contain other actions
- **Security Findings**: Issues discovered by scanners
- **Consolidated Report**: Combined results from all scanners

---

*This documentation should serve as your complete reference guide for understanding, maintaining, and extending the ActSpect project. Keep it updated as the project evolves!*
