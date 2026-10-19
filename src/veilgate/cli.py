"""Command-line interface (CLI) for Veilgate Gateway."""

import asyncio
import base64
import json
import os
from pathlib import Path
import sys
from typing import Annotated, Optional

import typer
import yaml

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import Transport, UpstreamSpec, VeilgatePolicy
from veilgate.config.settings import VeilgateSettings
from veilgate.gateway import create_gateway_pipeline, create_gateway_server
from veilgate.security.crypto import resolve_master_key
from veilgate.services.explain_service import ExplainService

app = typer.Typer(
    name="veilgate",
    help="Veilgate: Local-First Zero-Trust MCP Privacy Firewall & Context-Diet Gateway.",
    no_args_is_help=True,
)


@app.command()
def keygen() -> None:
    """Generate a new 32-byte AES-GCM master key and provision to OS keyring / fallback file."""
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode("utf-8")
    resolve_master_key(b64_key)
    typer.echo(f"Master key generated and securely provisioned:\n{b64_key}")


@app.command()
def validate(
    config: Annotated[
        Path,
        typer.Option("--config", "-c", help="Path to policy.yaml"),
    ] = Path("./policy.yaml"),
) -> None:
    """Validate and compile 3-layer policy document."""
    loader = PolicyLoader(policy_path=config)
    try:
        policy = loader.load(force_reload=True)
        typer.echo(
            f"Policy '{config}' is valid!\n"
            f"- Extends: {policy.extends}\n"
            f"- Upstreams ({len(policy.upstreams)}): {[u.id for u in policy.upstreams]}\n"
            f"- Protect keywords: {policy.protect}\n"
            f"- Drop keywords: {policy.drop}\n"
            f"- Tool rules: {len(policy.tools)}\n"
            f"- Learned grants: {len(policy.learned_grants)}"
        )
    except Exception as e:
        typer.secho(f"Policy validation failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e


@app.command()
def explain(
    target: Annotated[str, typer.Argument(help="Tool name (e.g. invoicedb.get_invoice) or JSON string")],
    config: Annotated[
        Path,
        typer.Option("--config", "-c", help="Path to policy.yaml"),
    ] = Path("./policy.yaml"),
) -> None:
    """Offline sub-50ms zero-LLM policy debugger for tools and payload shapes."""
    loader = PolicyLoader(policy_path=config)
    policy = loader.load()

    # Create lightweight explain pipeline
    settings = VeilgateSettings(policy_path=config)

    async def _run_explain() -> None:
        pipeline, _ = await create_gateway_pipeline(settings, policy=policy, policy_loader=loader)
        explain_svc = ExplainService(policy, pipeline.acl, pipeline.catalog_svc)

        # Check if target is JSON payload or tool name
        target_str = target.strip()
        if target_str.startswith("{"):
            try:
                payload = json.loads(target_str)
                explanations = explain_svc.explain_payload(payload)
                typer.echo(json.dumps([e.model_dump() for e in explanations], indent=2))
                return
            except json.JSONDecodeError:
                pass

        tool_exp = explain_svc.explain_tool(target_str)
        typer.echo(json.dumps(tool_exp.model_dump(), indent=2))

    asyncio.run(_run_explain())


@app.command()
def adopt(
    client: Annotated[str, typer.Option("--client", help="Target client: cursor or claude")] = "cursor",
    mcp_json: Annotated[Optional[Path], typer.Option("--mcp-json", help="Explicit path to client mcp.json")] = None,
    output_policy: Annotated[Path, typer.Option("--output", "-o", help="Where to save policy.yaml")] = Path("./policy.yaml"),
) -> None:
    """Auto-import upstream MCP servers from Cursor or Claude Desktop and rewire client."""
    # Determine target mcp.json path
    target_path = mcp_json
    if not target_path:
        if client.lower() == "cursor":
            target_path = Path(".cursor/mcp.json")
        elif client.lower() == "claude":
            appdata = os.environ.get("APPDATA", "~")
            target_path = Path(appdata) / "Claude" / "claude_desktop_config.json"
        else:
            typer.secho("Unsupported client. Choose 'cursor' or 'claude'.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    if not target_path.exists():
        typer.secho(f"Target config '{target_path}' not found.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    with open(target_path, "r", encoding="utf-8") as f:
        client_config = json.load(f)

    servers = client_config.get("mcpServers", {})
    if not servers:
        typer.secho("No 'mcpServers' entries found to adopt.", fg=typer.colors.YELLOW)
        return

    # Filter out existing veilgate entry if present
    upstream_specs: list[dict[str, object]] = []
    for srv_id, srv_def in servers.items():
        if srv_id.lower() == "veilgate":
            continue
        # Sanitize id for unambiguous namespacing (no underscores)
        clean_id = srv_id.lower().replace("_", "")
        spec: dict[str, object] = {
            "id": clean_id,
            "transport": "stdio",
            "command": srv_def.get("command", "python"),
            "args": srv_def.get("args", []),
        }
        if "env" in srv_def:
            spec["env"] = srv_def["env"]
        upstream_specs.append(spec)

    minimal_policy = {
        "version": "1",
        "extends": "recommended",
        "upstreams": upstream_specs,
        "protect": ["deal_margin", "salary_band", "diagnosis"],
        "drop": ["internal_row_id", "audit_metadata"],
    }

    # Save policy.yaml
    with open(output_policy, "w", encoding="utf-8") as f:
        yaml.safe_dump(minimal_policy, f, sort_keys=False)
    typer.echo(f"SUCCESS | Adopted {len(upstream_specs)} upstreams into {output_policy}")

    # Back up original client config
    bak_path = target_path.with_suffix(".veilgate.bak.json")
    with open(bak_path, "w", encoding="utf-8") as f:
        json.dump(client_config, f, indent=2)
    typer.echo(f"Backed up original client configuration to {bak_path}")

    # Rewire client config to Veilgate gateway
    client_config["mcpServers"] = {
        "veilgate": {
            "command": "uvx",
            "args": ["veilgate", "run", "--config", str(output_policy.resolve())],
        }
    }
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(client_config, f, indent=2)
    typer.echo(f"SUCCESS | Rewired {target_path} to route through Veilgate Gateway!")


@app.command()
def audit(
    action: Annotated[str, typer.Argument(help="Action: verify or list")] = "verify",
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
) -> None:
    """Inspect and cryptographically verify the tamper-evident audit trail."""
    settings = VeilgateSettings(db_path=db_path)

    async def _audit() -> None:
        from veilgate.repositories.audit_repo import AuditRepository
        from veilgate.repositories.db import DatabaseManager

        mgr = DatabaseManager(settings.db_path)
        await mgr.initialize()
        repo = AuditRepository(mgr)

        if action == "verify":
            is_valid, err = await repo.verify_chain()
            if is_valid:
                typer.secho("Cryptographic audit hash chain is INTACT and verified! No tampering detected.", fg=typer.colors.GREEN)
            else:
                typer.secho(f"SECURITY ALERT: Audit chain verification failed! {err}", fg=typer.colors.RED)
                raise typer.Exit(code=1)
        elif action == "list":
            events = await repo.list_events(limit=20)
            for ev in events:
                typer.echo(f"[{ev.ts}] seq={ev.seq} kind={ev.kind} tool={ev.qualified_ref} reason={ev.reason}")

    asyncio.run(_audit())


@app.command()
def run(
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to policy.yaml")] = Path("./policy.yaml"),
    dev: Annotated[bool, typer.Option("--dev", help="Enable interactive dev mode with learning")] = False,
    transport: Annotated[str, typer.Option("--transport", help="Transport mode: stdio or http")] = "stdio",
) -> None:
    """Start the Veilgate Gateway server."""
    settings = VeilgateSettings(policy_path=config, dev_mode=dev)
    loader = PolicyLoader(policy_path=config)

    async def _start() -> None:
        pipeline, _ = await create_gateway_pipeline(settings, policy_loader=loader)
        server = create_gateway_server(settings, pipeline)

        if transport.lower() == "http":
            typer.echo(f"Starting Veilgate Streamable HTTP Gateway on port {settings.http_port}...")
            await server.run_async(transport="streamable-http", port=settings.http_port)
        else:
            # stdio transport (single-line JSON logging strictly to stderr)
            await server.run_async(transport="stdio")

    asyncio.run(_start())


if __name__ == "__main__":
    app()
