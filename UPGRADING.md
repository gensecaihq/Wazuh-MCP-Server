# Upgrading

## Upgrading to 4.3.0

4.3.0 is backward compatible at the protocol and API level, but three behaviors
that were already the intended design are now **enforced**. Review these before
upgrading a production deployment.

### 1. Write access is opt-in (RBAC fails closed)

A token with **no scope claim is read-only**. The 14 state-changing tools (active
response + rollback) now require the `wazuh:write` scope, which must be granted
explicitly. If you relied on unscoped tokens implicitly having write access, grant
it:

```env
MCP_API_KEY_SCOPES=wazuh:read wazuh:write
```

In authless mode (`AUTH_MODE=none`), write tools are disabled unless
`AUTHLESS_ALLOW_WRITE=true`.

### 2. `AUTH_SECRET_KEY` is required in production

With `ENVIRONMENT=production` and `AUTH_MODE` other than `none`, the server refuses
to start without `AUTH_SECRET_KEY`. Set a stable secret (the same value across
replicas), otherwise tokens are invalidated on every restart:

```env
AUTH_SECRET_KEY=<32+ char secret>
```

### 3. Alerts come from the Indexer, not the Manager

The Manager REST API removed `/alerts` in Wazuh 4.8. Alert, aggregation,
vulnerability, and alert-backed compliance tools require the Wazuh Indexer:

```env
WAZUH_INDEXER_HOST=<indexer-host>
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASS=<pass>
```

Without it, those tools return a clear "Indexer not configured" error rather than
silently empty results.

### Active-response rollback tools

`wazuh_firewall_allow` and `wazuh_host_allow` no longer silently re-block an
address. Stock Wazuh cannot remove a firewall-drop / hosts.deny block through the
API, so these tools now require an operator-deployed undo script named via
`WAZUH_AR_FIREWALL_UNDO_COMMAND` / `WAZUH_AR_HOSTDENY_UNDO_COMMAND`, or they refuse
with an actionable error. Alternatively, configure `<active-response><timeout>` in
the manager so blocks expire automatically.

### MCP protocol

No action required. The server now speaks the 2026-07-28 revision on the stateless
per-request path and continues to answer the `initialize` handshake for clients on
2024-11-05 through 2025-11-25.
