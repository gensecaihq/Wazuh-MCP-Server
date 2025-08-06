# Contributing to Wazuh MCP Server

Welcome to the Wazuh MCP Server project! This guide will help you understand the repository structure, contribution workflow, and release process.

## 📋 Table of Contents

1. [Repository Overview](#repository-overview)
2. [Branch Strategy](#branch-strategy)
3. [Development Setup](#development-setup)
4. [Repository Structure](#repository-structure)
5. [Development Workflow](#development-workflow)
6. [Testing Guidelines](#testing-guidelines)
7. [Release Logic](#release-logic)
8. [Code Standards](#code-standards)
9. [Documentation](#documentation)
10. [Getting Help](#getting-help)

## 🏗️ Repository Overview

This repository contains two distinct implementations of the Wazuh MCP Server:

- **`main` branch**: FastMCP STDIO transport implementation (v2.x.x)
- **`mcp-remote` branch**: MCP-compliant remote server with SSE transport (v3.x.x)

Both implementations share the same core Wazuh integration but use different transport mechanisms for Claude Desktop integration.

## 🌳 Branch Strategy

### Main Branches
- **`main`**: Production-ready FastMCP STDIO implementation
- **`mcp-remote`**: Production-ready remote MCP server implementation

### Development Flow
- Feature branches: `feature/feature-name`
- Bugfix branches: `fix/issue-description`
- Hotfix branches: `hotfix/urgent-fix`

### Branch Protection Rules
- All changes must go through Pull Requests
- CI/CD must pass before merging
- Code review required from maintainers
- Branch protection enforced on main branches

## 🛠️ Development Setup

### Prerequisites
- **Python 3.9+** (3.11+ recommended)
- **Git** with GitHub access
- **Docker** (for mcp-remote development)
- **Node.js** (for pre-commit hooks)

### Quick Setup
```bash
# 1. Fork and clone the repository
git clone https://github.com/your-username/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Set up the development environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install -e ".[dev]"

# 4. Set up pre-commit hooks
pre-commit install

# 5. Choose your development branch
git checkout main          # For STDIO development
# OR
git checkout mcp-remote    # For remote MCP development
```

### Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit with your Wazuh server details
# See USER_GUIDE.md for detailed configuration options
```

## 📂 Repository Structure

```
Wazuh-MCP-Server/
├── .github/                    # GitHub Actions workflows
│   └── workflows/
│       ├── ci.yml             # Continuous Integration
│       ├── release.yml        # Release automation
│       ├── security.yml       # Security scanning
│       └── branch-sync.yml    # Branch synchronization
├── src/wazuh_mcp_server/      # Main source code
│   ├── __init__.py
│   ├── __main__.py            # Entry point
│   ├── main.py                # FastMCP server (main branch)
│   ├── server.py              # Remote MCP server (mcp-remote)
│   ├── config.py              # Configuration management
│   ├── api/                   # Wazuh API clients
│   ├── tools/                 # MCP tool implementations
│   ├── scripts/               # Utility scripts
│   └── utils/                 # Shared utilities
├── tests/                     # Test suite
├── tools/                     # Development tools
│   ├── branch-sync.py         # Branch synchronization
│   └── version-manager.py     # Version management
├── docs/                      # Documentation
├── docker/                    # Docker configurations (mcp-remote)
├── pyproject.toml            # Python project configuration
├── README.md                 # Branch-specific documentation
├── CONTRIBUTING.md           # This file
├── USER_GUIDE.md            # User installation guide
└── .env.example             # Environment template
```

### Key Files by Branch

**Main Branch (STDIO)**:
- `src/wazuh_mcp_server/main.py` - FastMCP server implementation
- `pyproject.toml` - Dependencies for STDIO transport
- `README.md` - STDIO-focused documentation

**MCP-Remote Branch (SSE)**:
- `src/wazuh_mcp_server/server.py` - Remote MCP server implementation
- `Dockerfile` - Container configuration
- `compose.yml` - Docker Compose setup
- `README.md` - Remote MCP-focused documentation

## 🔄 Development Workflow

### 1. Choose Your Implementation
Decide which version you want to contribute to:
- **STDIO Version** (main): Local Claude Desktop integration
- **Remote Version** (mcp-remote): Network-based MCP server

### 2. Create Feature Branch
```bash
# From the target branch (main or mcp-remote)
git checkout -b feature/your-feature-name

# Make your changes
# ...

# Commit with conventional commits
git commit -m "feat: add new security tool for vulnerability scanning"
```

### 3. Testing Your Changes
```bash
# Run tests
pytest tests/ -v

# Run linting
ruff check src/
black src/
mypy src/

# Test the specific implementation
# For STDIO (main branch):
wazuh-mcp-server --check

# For Remote (mcp-remote branch):
docker compose up -d --build
curl http://localhost:3000/health
```

### 4. Submit Pull Request
- Push your branch to your fork
- Create PR against the appropriate target branch
- Fill out the PR template completely
- Ensure all CI checks pass

## 🧪 Testing Guidelines

### Test Structure
```
tests/
├── unit/                  # Unit tests
├── integration/           # Integration tests
├── fixtures/             # Test data
└── conftest.py           # Pytest configuration
```

### Running Tests
```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# With coverage
pytest tests/ --cov=src/wazuh_mcp_server --cov-report=html

# Specific test file
pytest tests/unit/test_wazuh_client.py -v
```

### Test Requirements
- All new features must include tests
- Maintain >90% code coverage
- Include both positive and negative test cases
- Mock external dependencies (Wazuh API calls)

## 🚀 Release Logic

### Version Strategy
- **Main Branch**: Semantic versioning `2.x.x`
  - `2.1.0` - Current stable STDIO version
  - `2.x.x` - Future STDIO releases
  
- **MCP-Remote Branch**: Semantic versioning `3.x.x`
  - `3.0.0` - Current stable remote version  
  - `3.x.x` - Future remote releases

### Release Process
1. **Automated Releases**: Triggered by version tags
   ```bash
   # STDIO release (main branch)
   git tag v2.1.1
   git push origin v2.1.1
   
   # Remote release (mcp-remote branch) 
   git tag remote-v3.0.1
   git push origin remote-v3.0.1
   ```

2. **Manual Releases**: Via GitHub Actions workflow dispatch
   - Navigate to Actions → Release Pipeline
   - Select branch and version
   - Trigger manual release

### Release Artifacts
- **STDIO**: PyPI package (`pip install wazuh-mcp-server`)
- **Remote**: Docker image + PyPI package
- **Both**: GitHub release with binaries

## 📝 Code Standards

### Python Code Style
- **Black**: Code formatting (line length: 88)
- **Ruff**: Linting and import sorting
- **mypy**: Type checking
- **Docstrings**: Google style for all public functions

### Git Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```bash
feat: add new vulnerability scanning tool
fix: resolve connection timeout in Wazuh client
docs: update installation instructions
test: add unit tests for alert filtering
chore: update dependencies
```

### Code Review Checklist
- [ ] Code follows style guidelines
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] No hardcoded secrets or credentials
- [ ] Error handling is appropriate
- [ ] Performance impact considered

## 📚 Documentation

### Documentation Types
1. **Code Documentation**: Inline docstrings and comments
2. **API Documentation**: Auto-generated from docstrings
3. **User Documentation**: Installation and usage guides
4. **Developer Documentation**: Architecture and contribution guides

### Documentation Standards
- Keep README.md branch-specific
- Update CHANGELOG.md for releases
- Include code examples in docstrings
- Document configuration options
- Provide troubleshooting sections

## 🆘 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Pull Request Reviews**: Code-specific discussions

### Issue Templates
When creating issues, use the appropriate template:
- **Bug Report**: For reporting bugs
- **Feature Request**: For suggesting enhancements
- **Security Issue**: For security-related concerns

### Development Questions
Before asking for help:
1. Check existing issues and discussions
2. Review this contributing guide
3. Check the USER_GUIDE.md for setup issues
4. Review the code and tests for similar patterns

## 🏆 Recognition

Contributors are recognized in:
- CHANGELOG.md for releases
- GitHub contributors page
- Special recognition for significant contributions

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to the Wazuh MCP Server project!**

For questions about this guide, please open an issue or start a discussion.