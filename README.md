# Veilgate

**Local-First Zero-Trust MCP Privacy Firewall & Context-Diet Gateway**

Veilgate sits as an intelligent Man-in-the-Middle (MITM) proxy between AI hosts (Claude Desktop, Cursor, LangGraph) and upstream Model Context Protocol (MCP) tool servers. It enforces:
- **Dynamic Context Diet:** Prunes 40-70% of prompt token bloat via lossless schema compaction and adaptive ranking.
- **Data Minimization & Synthetic Tokens:** Replaces sensitive PII/secrets with format-preserving `<vg:TYPE:ID>` tokens before raw payloads reach cloud LLMs.
- **Deterministic Taint Tracking:** Prevents Confused Deputy attacks by blocking token re-hydration into unauthorized external sinks (`send_email`, web fetch).
- **Tamper-Evident Hash Chaining:** Cryptographically links all gateway events via SHA-256 in a local SQLite WAL ledger.
- **Zero-Config Developer Experience:** Adopt existing MCP configs in seconds via `uvx veilgate adopt`.
