# Veilgate

**A local-first zero-trust [Model Context Protocol (MCP)](https://modelcontextprotocol.io) privacy firewall & context-diet gateway.**

[![PyPI Version](https://img.shields.io/pypi/v/veilgate.svg)](https://pypi.org/project/veilgate/)
[![Python Versions](https://img.shields.io/pypi/pyversions/veilgate.svg)](https://pypi.org/project/veilgate/)
[![License](https://img.shields.io/pypi/l/veilgate.svg)](https://github.com/OmH3/Veilgate/blob/main/LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/OmH3/Veilgate/actions)

---

## Overview

**Veilgate** is a local-first zero-trust security gateway and proxy that sits transparently between AI client hosts (Claude Desktop, Cursor, Antigravity, Windsurf, LangGraph) and upstream Model Context Protocol (MCP) tool servers.

As AI agents connect to databases, filesystems, and external APIs via MCP, they introduce four major risks:

1. **Unchecked Data Exfiltration:** Upstream tools can leak PII, credentials, and financial records directly into LLM context windows.
2. **Cross-MCP Confused Deputy Attacks:** Sensitive outputs from an internal MCP server can be forwarded by an agent into an external MCP sink (email, Slack, HTTP, webhooks).
3. **Rug-Pull Tool Mutation:** Compromised MCP servers can silently alter tool schemas or inject hidden prompt instructions after initial approval.
4. **Context Window Token Bloat:** Large MCP tool catalogs can consume 40–70% of the prompt context window before reasoning begins.

### Key Capabilities

- **Cryptographic Data Minimization (`protect` & `drop`):** Intercepts sensitive fields and inline PII/secrets, encrypts raw values locally in an AES-256-GCM vault, and replaces them with format-preserving synthetic tokens (`<vg:SALARY:101YJQ>`, `<vg:SSN:F36N37>`) while stripping unnecessary bloat fields.
- **Cross-MCP Taint Tracking & Egress Guard:** Tracks token provenance across MCP servers and blocks unauthorized attempts to pass vaulted tokens into external or untrusted sinks (`TAINT_ARG_GUARD_BLOCKED`), while transparently rehydrating authorized tokens for trusted internal tools.
- **Native Human-in-the-Loop (HITL) Approval Modal & Web Dashboard:** Pauses guarded or high-risk tool calls and prompts the human reviewer via an always-on-top native GUI popup modal (or the local web dashboard) with **`[1] Allow Once`**, **`[2] Allow Always`**, or **`[3] Deny`**.
- **Lossless Context Diet:** Compacts verbose JSON schemas and uses BM25 adaptive search (`veilgate_search_tools`) to keep agent context windows lean.
- **Rug-Pull & Prompt Injection Defense:** Pins SHA-256 tool schema fingerprints and scans descriptions for hidden instructions or Unicode tag smuggling.
- **Tamper-Evident Audit Ledger:** Records every discovery, tool call, token transformation, and approval decision in an append-only, HMAC/SHA-256 hash-chained SQLite WAL ledger.

---

## Installation

Requires **Python 3.11+**.

```bash
# Standard installation
pip install veilgate

# Or install with uv
uv pip install veilgate

# Or run directly without installing
uvx veilgate --help
```

---

## Quickstart

### 1. Initialize a Starter Policy

Generate a `policy.yaml` file in your workspace:

```bash
veilgate init --output policy.yaml
```

*(Optional)* Provision a dedicated 32-byte AES-256-GCM master key in your OS keyring:

```bash
veilgate keygen
```

### 2. Configure Upstream MCP Servers & Rules (`policy.yaml`)

Define the upstream MCP servers Veilgate should proxy, which tools require human approval, and which fields to tokenize (`protect`) or strip (`drop`):

```yaml
version: '1'
extends: recommended
default_tool_allow: true

upstreams:
  - id: fs
    transport: stdio
    command: npx
    args:
      - -y
      - "@modelcontextprotocol/server-filesystem"
      - "/path/to/workspace"
  - id: db
    transport: stdio
    command: uvx
    args:
      - mcp-server-motherduck
      - --db-path
      - ":memory:"

tools:
  - match: "fs.write_file"
    allow: true
    require_approval: true
  - match: "db.query"
    allow: true
    require_approval: true

protect:
  - margin
  - salary
  - ssn
  - secret
  - password
  - token

drop:
  - debug_trace
  - internal_id
```

Validate your policy at any time:

```bash
veilgate validate --config policy.yaml
```

### 3. Connect Your AI Client (`mcp.json` / `mcp_config.json`)

Point your MCP client host (Claude Desktop, Cursor, Antigravity, etc.) to `veilgate run`:

```json
{
  "mcpServers": {
    "veilgate": {
      "command": "veilgate",
      "args": [
        "run",
        "--config",
        "/absolute/path/to/policy.yaml"
      ]
    }
  }
}
```

Or automatically import and rewire an existing Cursor or Claude Desktop config:

```bash
veilgate adopt --client cursor --output policy.yaml
```

---

## Interactive Human-in-the-Loop (HITL) Approvals

When an AI agent invokes a tool marked with `require_approval: true` (or an external egress tool), Veilgate pauses the call and displays a native authorization modal (and queues the request in the local dashboard):

| Option | Decision State | Behavior |
| :--- | :--- | :--- |
| **`[1] Allow Once`** | `APPROVED` | Authorizes this single tool invocation (bound to the exact SHA-256 hash of its arguments). Future calls will prompt again. |
| **`[2] Allow Always`** | `APPROVED_AND_SAVED` | Authorizes the call and updates `policy.yaml` (`require_approval: false`) with live hot-reload so future calls to that tool execute without prompting. |
| **`[3] Deny`** | `DENIED` | Immediately blocks the tool call (`APPROVAL_DENIED`) before any upstream execution occurs and logs the event. |

All approval requests are fail-closed: if the timeout expires (default: `120s`) without human confirmation, Veilgate automatically denies the call (`APPROVAL_TIMEOUT`).

---

## CLI Reference

```bash
# Start the Veilgate MCP Gateway proxy (stdio or streamable HTTP)
veilgate run --config policy.yaml

# Wrap a single MCP command on the fly without writing a config file
veilgate run --wrap "npx -y @modelcontextprotocol/server-filesystem ."

# Validate and inspect a compiled policy
veilgate validate --config policy.yaml

# Inspect upstream tool catalog, capabilities, risk ratings, and token counts
veilgate catalog list --config policy.yaml

# Test how Veilgate will classify a tool or sanitize a sample JSON payload
veilgate explain db.query --config policy.yaml
veilgate explain '{"customer": "Alice", "salary": "$145,000", "debug_trace": " verbose "}' --config policy.yaml

# Launch the local web observability and review dashboard (http://127.0.0.1:8765)
veilgate dashboard --config policy.yaml --port 8765

# Verify the cryptographic integrity of the SHA-256 audit hash chain
veilgate audit verify --db veilgate.db

# Tail or export audit logs (JSONL or CSV)
veilgate audit tail --db veilgate.db
veilgate audit export --db veilgate.db --output audit.jsonl --format jsonl
```

---

## Links & Support

- **Source Code & Documentation:** [https://github.com/OmH3/Veilgate](https://github.com/OmH3/Veilgate)
- **Issue Tracker:** [https://github.com/OmH3/Veilgate/issues](https://github.com/OmH3/Veilgate/issues)
- **Model Context Protocol:** [https://modelcontextprotocol.io](https://modelcontextprotocol.io)

## License

Released under the [MIT License](https://github.com/OmH3/Veilgate/blob/main/LICENSE).
