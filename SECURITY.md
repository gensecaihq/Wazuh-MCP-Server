# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.3.x   | Yes       |
| 4.2.x   | Security fixes only |
| < 4.2   | No        |

## Reporting a Vulnerability

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/gensecaihq/Wazuh-MCP-Server/security/advisories/new) ("Report a vulnerability" on the repository's Security tab). Do not open a public issue for security reports.

Include what you can of the following:

- Affected version(s) and deployment mode (stdio / remote HTTP, auth mode)
- Reproduction steps or a proof of concept
- Impact assessment (what an attacker gains)

You can expect an acknowledgment within 72 hours and a fix or mitigation plan within 14 days for confirmed issues. Credit is given in the changelog and release notes unless you ask otherwise.

## Scope

In scope: authentication/authorization bypass (API key, OAuth 2.1, RBAC scopes), credential exposure in logs or responses, injection via tool parameters, SSRF through Wazuh connection settings, and container/deployment hardening gaps in the shipped configs.

Out of scope: vulnerabilities in Wazuh itself (report to the [Wazuh project](https://github.com/wazuh/wazuh/security)), issues requiring a compromised host, and denial of service against your own deployment.

## Hardening Guidance

See [docs/security/README.md](docs/security/README.md) for deployment hardening: TLS, service accounts with least privilege, RBAC scopes, and network isolation.
