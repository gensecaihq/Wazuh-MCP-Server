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

This repository contains a production-ready MCP-compliant remote server implementation:

- **`main` branch**: MCP-compliant remote server with SSE transport (v4.x.x)

The implementation provides enterprise-grade integration between Claude Desktop and Wazuh SIEM platform using HTTP/SSE transport.

## 🌳 Branch Strategy

### Main Branch
- **`main`**: Production-ready MCP remote server implementation

### Development Flow
- Feature branches: `feature/feature-name`
- Bugfix branches: `fix/issue-description`
- Hotfix branches: `hotfix/urgent-fix`

### Branch Protection Rules
- All changes must go through Pull Requests
- CI/CD must pass before merging
- Code review required from maintainers
- Branch protection enforced on main branch

## 🛠️ Development Setup

### Prerequisites
- **Python 3.13+** recommended
- **Git** with GitHub access
- **Docker 20.10+** with Compose v2.20+
- **Node.js** (for pre-commit hooks)

### Quick Setup
```bash
# 1. Fork and clone the repository
git clone https://github.com/your-username/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Set up the development environment (for native development)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install -r requirements.txt

# 4. For Docker development (recommended)
docker compose -f compose.dev.yml up -d --build
```

### Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit with your Wazuh server details
# See INSTALLATION.md for detailed configuration options
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
│   ├── server.py              # MCP remote server with SSE
│   ├── config.py              # Configuration management
│   ├── api/                   # Wazuh API clients
│   ├── tools/                 # MCP tool implementations
│   ├── scripts/               # Utility scripts
│   └── utils/                 # Shared utilities
├── tests/                     # Test suite
├── tools/                     # Development tools
│   ├── branch-sync.py         # Branch synchronization
│   └── version-manager.py     # Version management
├── Dockerfile                # Docker container configuration
├── compose.yml              # Docker Compose setup
├── compose.dev.yml          # Development Docker Compose
├── deploy-production.sh     # Production deployment script
├── install.sh               # Installation script
├── pyproject.toml          # Python project configuration
├── README.md               # Main documentation
├── CONTRIBUTING.md         # This file
├── INSTALLATION.md         # Installation guide
└── .env.example           # Environment template
```

### Key Files

**Core Application**:
- `src/wazuh_mcp_server/server.py` - MCP remote server implementation with SSE
- `src/wazuh_mcp_server/__main__.py` - Application entry point
- `src/wazuh_mcp_server/config.py` - Configuration management

**Deployment**:
- `Dockerfile` - Production container configuration
- `compose.yml` - Docker Compose production setup
- `deploy-production.sh` - Automated deployment script

**Documentation**:
- `README.md` - Main project documentation
- `INSTALLATION.md` - Detailed installation guide
- `MCP_COMPLIANCE_VERIFICATION.md` - MCP compliance details

## 🔄 Development Workflow

### 1. Create Feature Branch
```bash
# From main branch
git checkout main
git pull origin main
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

# Test the MCP remote server
docker compose up -d --build
curl http://localhost:3000/health

# Test SSE endpoint
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
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
- **Main Branch**: Semantic versioning `4.x.x`
  - `4.0.0` - Current stable MCP remote server version
  - `4.x.x` - Future releases with SSE transport

### Release Process
1. **Automated Releases**: Triggered by version tags
   ```bash
   # Create and push version tag
   git tag v4.0.1
   git push origin v4.0.1

   # GitHub Actions will automatically:
   # - Build Docker image
   # - Run tests
   # - Create GitHub release
   ```

2. **Manual Releases**: Via GitHub Actions workflow dispatch
   - Navigate to Actions → Release Pipeline
   - Trigger manual release

### Release Artifacts
- Docker image (via GitHub Container Registry)
- GitHub release with deployment scripts
- Documentation and compliance verification

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