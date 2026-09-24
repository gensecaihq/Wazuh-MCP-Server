# Contributing to Wazuh MCP Server

This guide covers the development setup, repository layout, checks a change must pass, and how releases are cut.

## Contents

1. [Development setup](#development-setup)
2. [Repository layout](#repository-layout)
3. [Workflow](#workflow)
4. [Testing](#testing)
5. [Code standards](#code-standards)
6. [Adding or changing a tool](#adding-or-changing-a-tool)
7. [Documentation](#documentation)
8. [Releases](#releases)
9. [Getting help](#getting-help)

## Development setup

Prerequisites:

- Python 3.11 or later (CI tests 3.11, 3.12 and 3.13)
- Git
- Docker with Compose v2 (for container testing)

```bash
git clone https://github.com/<your-username>/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Package plus pytest, pytest-asyncio, pytest-cov, black, isort, ruff and gcf-python
pip install -e ".[dev]"
```

Copy the environment template and fill in your Wazuh details (see [docs/configuration.md](docs/configuration.md)):

```bash
cp .env.example .env
```

To run the server directly:

```bash
python -m wazuh_mcp_server
```

Outside `ENVIRONMENT=production`, a missing `AUTH_SECRET_KEY` or `MCP_API_KEY` is generated per process and the API key is printed at startup. For work that does not need authentication, `AUTH_MODE=none` serves read-only tools without a token.

For a container build, `compose.dev.yml` mounts `./src` read-only and runs with `ENVIRONMENT=development` and `LOG_LEVEL=DEBUG`. It does not auto-reload; restart the container after editing:

```bash
docker compose -f compose.dev.yml up -d --build
docker compose -f compose.dev.yml restart
```

## Repository layout

```
Wazuh-MCP-Server/
├── src/wazuh_mcp_server/
│   ├── __main__.py         # Entry point (python -m wazuh_mcp_server)
│   ├── server.py           # FastAPI app, MCP protocol handling, tool definitions and dispatch
│   ├── toolsets.py         # Toolset membership, WAZUH_TOOLSETS resolution, tool annotations
│   ├── auth.py             # API keys and bearer JWTs
│   ├── oauth.py            # OAuth 2.0 authorization server
│   ├── config.py           # Environment configuration and startup validation
│   ├── security.py         # Rate limiting, CORS, input validation, log redaction
│   ├── clusters.py         # Multi-cluster registry
│   ├── session_store.py    # In-memory and Redis session storage
│   ├── resilience.py       # Circuit breakers, retries, graceful shutdown
│   ├── monitoring.py       # Prometheus metrics, structured logging
│   ├── gcf_format.py       # Optional GCF response encoding
│   └── api/                # Wazuh Manager and Indexer clients
├── tests/integration/      # Test suite (protocol, auth, OAuth, tools, active response, resilience)
├── evals/                  # Tool-selection eval for models (tool_selection.py, scenarios.json)
├── config/                 # clusters.json.example
├── docs/                   # Guides and per-tool API reference
├── .github/workflows/      # ci.yml, security.yml, docker-publish.yml, release.yml, update-contributors.yml
├── Dockerfile
├── compose.yml             # Production-style deployment (ENVIRONMENT=production, loopback bind)
├── compose.dev.yml         # Development container
├── compose.local-llm.yml   # vLLM + Open WebUI overlay
├── deploy.py, deploy.bat   # Scripted Docker deployment
├── pyproject.toml
└── requirements.txt        # Runtime dependencies installed in the Docker image
```

## Workflow

1. Branch from `main`: `feature/<name>`, `fix/<name>` or `docs/<name>`.
2. Make the change, with tests.
3. Run the same checks CI runs (below).
4. Open a pull request against `main`. All changes land through pull requests, and CI must pass.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add rule_groups filter to get_wazuh_alerts
fix: refuse positive duration on wazuh_block_ip
docs: correct Indexer settings in the configuration guide
test: cover refresh-token replay
chore: bump fastapi
```

## Testing

CI (`.github/workflows/ci.yml`) runs:

```bash
# Lint job (Python 3.13)
black --check --diff src/ tests/
isort --check-only --diff src/ tests/
ruff check src/

# Test job (Python 3.11, 3.12, 3.13)
pytest tests/ -v --cov=src/wazuh_mcp_server --cov-report=xml --cov-fail-under=50
```

Run them locally before pushing; to apply formatting instead of checking it, run `black src/ tests/` and `isort src/ tests/`.

Other useful invocations:

```bash
pytest tests/integration/test_mcp_protocol.py -v
pytest tests/ --cov=src/wazuh_mcp_server --cov-report=html
```

Expectations:

- New behaviour comes with tests, including the failure and refusal paths.
- Tests must not need a live Wazuh; mock the Manager and Indexer clients.
- Coverage must not drop below the CI floor.

The Security Audit workflow (`security.yml`) additionally runs pip-audit, Bandit, Semgrep, a Trivy image scan and a Dockerfile lint weekly and on pushes to `main` that touch Python, dependency or Dockerfile changes.

To smoke-test a running server:

```bash
curl http://localhost:3000/health
curl -s -X POST http://localhost:3000/auth/token -H 'Content-Type: application/json' \
  -d '{"api_key": "wazuh_..."}'
```

MCP traffic goes to `/mcp` (Streamable HTTP). `/sse` returns `410 Gone`.

## Code standards

- Formatting: Black, line length 120.
- Imports: isort with the Black profile.
- Linting: Ruff (rules E, F, W, I).
- Target Python 3.11; do not use syntax or stdlib features from later versions.
- Public functions get docstrings.
- No secrets, credentials or real hostnames in code, tests or examples.
- Tool output and log messages must not bypass redaction (`_sanitize_output_text` in `server.py` for tool results, the log filter in `security.py` for logs).

Review checklist:

- [ ] Checks above pass locally
- [ ] Tests cover the change, including negative cases
- [ ] Documentation and `CHANGELOG.md` (under *Unreleased*) are updated
- [ ] Errors are reported to the caller rather than swallowed
- [ ] No new unauthenticated or unscoped paths

## Adding or changing a tool

A tool must be registered in several places. `tests/integration/test_toolsets.py` checks that the toolsets and the scope sets cover the same tools and that no tool is in two toolsets.

1. Define the tool (name, description, `inputSchema` with `additionalProperties: false`) in `handle_tools_list` in `server.py`, and add its dispatch branch in the tool-call handler.
2. Add it to exactly one toolset in `toolsets.py`.
3. Add it to `READ_SCOPE_TOOLS` or `WRITE_SCOPE_TOOLS` in `server.py`. A tool in neither set is treated as write (fail closed).
4. For a write tool that undoes a containment action, add it to `REVERSAL_TOOLS` in `toolsets.py` so it is not annotated as destructive.
5. Validate every argument with the helpers in `security.py`.
6. Update the tool tables in `README.md`, the relevant page under `docs/api/`, and the tool count wherever it appears.
7. If models should be able to pick it, consider adding a scenario to `evals/scenarios.json`.

## Documentation

- `README.md` is the front page: overview, quick start, tool summary, security model, links.
- Detailed material lives in `docs/`: configuration reference, client guides, operations, troubleshooting, per-tool API reference.
- User-visible changes go in `CHANGELOG.md` under *Unreleased*; changes that need operator action also go in `UPGRADING.md`.
- Document behaviour as implemented. Commands and examples should be run before they are published.

## Releases

Versions follow [Semantic Versioning](https://semver.org/). The current release is listed in [CHANGELOG.md](CHANGELOG.md).

1. Set the version in `pyproject.toml` and `src/wazuh_mcp_server/__init__.py` (the release workflow fails if either differs from the tag), update the defaults in `Dockerfile`, `compose.yml` and `deploy.py`, and move the *Unreleased* changelog entries under the new version.
2. Tag and push:

   ```bash
   git tag v4.3.1
   git push origin v4.3.1
   ```

On a `v*.*.*` tag:

- `release.yml` checks that the tag matches both package versions, runs the tests, builds and checks the Python package, and creates a GitHub release. Publishing to PyPI runs only when the repository variable `PUBLISH_PYPI` is `true`.
- `docker-publish.yml` builds the image, scans it with Trivy, and pushes `linux/amd64` and `linux/arm64` images to `ghcr.io/gensecaihq/wazuh-mcp-server` tagged `X.Y.Z`, `X.Y` and `vX.Y.Z`. Pushes to `main` publish `latest` and `sha-<commit>`.

`release.yml` can also be started manually from the Actions tab (workflow dispatch).

## Getting help

- Bugs and feature requests: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues), using the bug report or feature request template.
- Questions: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions).
- Security vulnerabilities: report privately as described in [SECURITY.md](SECURITY.md); do not open a public issue.
- Setup problems: check [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) first.

Contributors are credited in the changelog and in the acknowledgments of the README and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
