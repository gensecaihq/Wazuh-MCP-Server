# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.3.x   | Yes       |
| 4.2.x   | Security fixes only |
| < 4.2   | No        |

The current release is 4.3.0. Fixes made after it are listed under "Unreleased" in
[CHANGELOG.md](CHANGELOG.md) until the next release.

## Reporting a Vulnerability

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/gensecaihq/Wazuh-MCP-Server/security/advisories/new) ("Report a vulnerability" on the repository's Security tab). Do not open a public issue for security reports.

Include what you can of the following:

- Affected version(s), deployment method (Docker image, compose, or Python package) and `AUTH_MODE`
- Reproduction steps or a proof of concept
- Impact assessment (what an attacker gains)

You can expect an acknowledgment within 72 hours and a fix or mitigation plan within 14 days for confirmed issues. Credit is given in the changelog and release notes unless you ask otherwise.

## Scope

In scope: authentication or authorization bypass (API keys, bearer JWTs, the OAuth authorization server including API-key and OpenID Connect sign-in, RBAC scopes); bypass of the active-response safeguards (confirmation gate, protected IP targets, the Manager-agent and fleet-wide opt-ins, quarantine path limits, the refusal of IP blocks through `wazuh_active_response`); Wazuh Manager or Indexer TLS verification being skipped while enabled; credential exposure in logs or tool output; injection via tool parameters; SSRF through Wazuh connection settings; and hardening gaps in the shipped container and compose configuration.

Out of scope: vulnerabilities in Wazuh itself (report to the [Wazuh project](https://github.com/wazuh/wazuh/security)), issues requiring a compromised host, denial of service against your own deployment, and the documented limitations in [docs/security/README.md](docs/security/README.md#known-limitations) (for example, Manager certificate verification being off while `WAZUH_ALLOW_SELF_SIGNED=true`).

## Hardening Guidance

See [docs/security/README.md](docs/security/README.md) for the security model and deployment hardening: authentication modes and OAuth sign-in, RBAC scopes, active-response safeguards, TLS verification toward Wazuh, least-privilege Wazuh accounts, and a production checklist.
