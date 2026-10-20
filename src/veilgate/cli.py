"""Command-line interface (CLI) for Veilgate Gateway."""

import asyncio
import base64
import json
import os
import shlex
import time
from pathlib import Path
from typing import Annotated

import numpy as np
import typer
import uvicorn
import yaml
from rich.console import Console
from rich.table import Table
from ulid import ULID

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import Transport, UpstreamSpec
from veilgate.config.settings import VeilgateSettings
from veilgate.dashboard.app import create_dashboard_app
from veilgate.gateway import create_gateway_pipeline, create_gateway_server
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.catalog_repo import CatalogRepository
from veilgate.repositories.db import DatabaseManager
from veilgate.security.crypto import resolve_master_key
from veilgate.services.explain_service import ExplainService
from veilgate.services.models import SessionContext, ToolRef

app = typer.Typer(
    name="veilgate",
    help="Veilgate: Local-First Zero-Trust MCP Privacy Firewall & Context-Diet Gateway.",
    no_args_is_help=True,
)

policy_app = typer.Typer(name="policy", help="Manage and promote Veilgate security policies.")
catalog_app = typer.Typer(name="catalog", help="Inspect, fingerprint, and approve tool catalogs.")
audit_app = typer.Typer(name="audit", help="Verify, export, and tail tamper-evident audit logs.")

app.add_typer(policy_app)
app.add_typer(catalog_app)
app.add_typer(audit_app)


@app.command()
def keygen() -> None:
    """Generate a new 32-byte AES-GCM master key and provision to OS keyring / fallback file."""
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode("utf-8")
    resolve_master_key(b64_key)
    typer.echo(f"Master key generated and securely provisioned:\n{b64_key}")


@policy_app.command("validate")
@app.command("validate")
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


@policy_app.command("init")
def policy_init(
    output_path: Annotated[Path, typer.Option("--output", "-o", help="Target path")] = Path("./policy.yaml"),
    profile: Annotated[str, typer.Option("--profile", "-p", help="Base profile: recommended or strict")] = "recommended",
) -> None:
    """Initialize a starter policy.yaml configuration file."""
    starter = {
        "version": "1",
        "extends": profile,
        "default_tool_allow": True,
        "upstreams": [],
        "protect": ["margin", "salary", "ssn", "secret"],
        "drop": ["debug_trace", "internal_id"],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(starter, f, sort_keys=False)
    typer.echo(f"SUCCESS | Created starter {profile} policy at {output_path}")


@policy_app.command("promote")
def policy_promote(
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to policy.yaml")] = Path("./policy.yaml"),
) -> None:
    """Promote interactive dev grants from policy.learned.yaml into policy.yaml."""
    loader = PolicyLoader(policy_path=config)
    count = loader.promote_learned_grants()
    typer.echo(f"SUCCESS | Promoted {count} learned grants into {config}")


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

    settings = VeilgateSettings(policy_path=config)

    async def _run_explain() -> None:
        pipeline, _ = await create_gateway_pipeline(settings, policy=policy, policy_loader=loader)
        explain_svc = ExplainService(policy, pipeline.acl, pipeline.catalog_svc)

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
    mcp_json: Annotated[Path | None, typer.Option("--mcp-json", help="Explicit path to client mcp.json")] = None,
    output_policy: Annotated[Path, typer.Option("--output", "-o", help="Where to save policy.yaml")] = Path("./policy.yaml"),
) -> None:
    """Auto-import upstream MCP servers from Cursor or Claude Desktop and rewire client."""
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

    with open(target_path, encoding="utf-8") as f:
        client_config = json.load(f)

    servers = client_config.get("mcpServers", {})
    if not servers:
        typer.secho("No 'mcpServers' entries found to adopt.", fg=typer.colors.YELLOW)
        return

    upstream_specs: list[dict[str, object]] = []
    for srv_id, srv_def in servers.items():
        if srv_id.lower() == "veilgate":
            continue
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

    with open(output_policy, "w", encoding="utf-8") as f:
        yaml.safe_dump(minimal_policy, f, sort_keys=False)
    typer.echo(f"SUCCESS | Adopted {len(upstream_specs)} upstreams into {output_policy}")

    bak_path = target_path.with_suffix(".veilgate.bak.json")
    with open(bak_path, "w", encoding="utf-8") as f:
        json.dump(client_config, f, indent=2)
    typer.echo(f"Backed up original client configuration to {bak_path}")

    client_config["mcpServers"] = {
        "veilgate": {
            "command": "uvx",
            "args": ["veilgate", "run", "--config", str(output_policy.resolve())],
        }
    }
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(client_config, f, indent=2)
    typer.echo(f"SUCCESS | Rewired {target_path} to route through Veilgate Gateway!")


@audit_app.command("verify")
def audit_verify(
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
) -> None:
    """Verify cryptographic audit hash chain integrity."""
    settings = VeilgateSettings(db_path=db_path)

    async def _verify() -> None:
        mgr = DatabaseManager(settings.db_path)
        await mgr.initialize()
        repo = AuditRepository(mgr)
        is_valid, err = await repo.verify_chain()
        if is_valid:
            typer.secho("Cryptographic audit hash chain is INTACT and verified! No tampering detected.", fg=typer.colors.GREEN)
        else:
            typer.secho(f"SECURITY ALERT: Audit chain verification failed! {err}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    asyncio.run(_verify())


@audit_app.command("list")
@app.command("audit")
def audit_list(
    action: Annotated[str, typer.Argument(help="Action: verify or list")] = "verify",
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of records")] = 20,
) -> None:
    """List or verify audit events."""
    settings = VeilgateSettings(db_path=db_path)

    async def _audit() -> None:
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
            events = await repo.list_events(limit=limit)
            for ev in events:
                typer.echo(f"[{ev.ts}] seq={ev.seq} kind={ev.kind} tool={ev.qualified_ref} reason={ev.reason}")

    asyncio.run(_audit())


@audit_app.command("tail")
def audit_tail(
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
    interval: Annotated[float, typer.Option("--interval", help="Polling interval in seconds")] = 1.0,
) -> None:
    """Tail audit events in real time."""
    settings = VeilgateSettings(db_path=db_path)

    async def _tail() -> None:
        mgr = DatabaseManager(settings.db_path)
        await mgr.initialize()
        repo = AuditRepository(mgr)
        last_seq = 0
        typer.echo("Tailing Veilgate audit stream (Ctrl+C to stop)...")

        while True:
            events = await repo.list_events(limit=20)
            new_events = [e for e in events if e.seq > last_seq]
            for ev in reversed(new_events):
                typer.echo(f"[{ev.ts}] seq={ev.seq} kind={ev.kind} tool={ev.qualified_ref} reason={ev.reason}")
                if ev.seq > last_seq:
                    last_seq = ev.seq
            await asyncio.sleep(interval)

    try:
        asyncio.run(_tail())
    except KeyboardInterrupt:
        typer.echo("\nStopped tailing audit log.")


@audit_app.command("export")
def audit_export(
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file path")] = Path("./audit_export.jsonl"),
    format_type: Annotated[str, typer.Option("--format", "-f", help="Format: jsonl or csv")] = "jsonl",
) -> None:
    """Export tamper-evident audit log to JSONL or CSV file."""
    settings = VeilgateSettings(db_path=db_path)

    async def _export() -> None:
        mgr = DatabaseManager(settings.db_path)
        await mgr.initialize()
        repo = AuditRepository(mgr)
        events = await repo.list_events(limit=100_000)

        with open(output, "w", encoding="utf-8") as f:
            if format_type.lower() == "csv":
                f.write("seq,ts,event_id,session_id,kind,qualified_ref,reason\n")
                for e in events:
                    f.write(f'{e.seq},{e.ts},{e.event_id},{e.session_id},{e.kind},{e.qualified_ref or ""},{e.reason}\n')
            else:
                for e in events:
                    f.write(e.model_dump_json() + "\n")

        typer.echo(f"SUCCESS | Exported {len(events)} audit records to {output}")

    asyncio.run(_export())


@catalog_app.command("approve")
def catalog_approve(
    tool: Annotated[str, typer.Argument(help="Qualified tool name to approve (e.g. invoicedb.get_invoice)")],
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
) -> None:
    """Approve a quarantined tool, pin its current schema fingerprint, and unquarantine it."""
    settings = VeilgateSettings(db_path=db_path)

    async def _approve() -> None:
        mgr = DatabaseManager(settings.db_path)
        await mgr.initialize()
        repo = CatalogRepository(mgr)
        entry = await repo.get_tool(tool)
        if not entry:
            typer.secho(f"Tool '{tool}' not found in catalog.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        # Update pinned_fp to current fingerprint and unquarantine
        updated = entry.model_copy(update={"pinned_fp": entry.fingerprint, "status": "active"})
        await repo.upsert_tool(updated)
        typer.secho(f"SUCCESS | Tool '{tool}' approved and pinned to fingerprint {entry.fingerprint[:12]}!", fg=typer.colors.GREEN)

    asyncio.run(_approve())


@catalog_app.callback(invoke_without_command=True)
def catalog_callback(
    ctx: typer.Context,
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to policy.yaml")] = Path("./policy.yaml"),
    from_mcp_json: Annotated[Path | None, typer.Option("--from-mcp-json", help="Path to mcp.json directly")] = None,
    shapes: Annotated[bool, typer.Option("--shapes", help="Display observed response JSON shapes and classifications")] = False,
) -> None:
    """Inspect and tabulate upstream tool capabilities, risk ratings, and trust profiles."""
    if ctx.invoked_subcommand is None:
        catalog_impl(config=config, from_mcp_json=from_mcp_json, shapes=shapes)


@catalog_app.command("list")
def catalog_list(
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to policy.yaml")] = Path("./policy.yaml"),
    from_mcp_json: Annotated[Path | None, typer.Option("--from-mcp-json", help="Path to mcp.json directly")] = None,
    shapes: Annotated[bool, typer.Option("--shapes", help="Display observed response JSON shapes and classifications")] = False,
) -> None:
    """List upstream tools registered in the catalog."""
    catalog_impl(config=config, from_mcp_json=from_mcp_json, shapes=shapes)


def catalog_impl(
    config: Path,
    from_mcp_json: Path | None,
    shapes: bool,
) -> None:
    """Implementation of catalog inspection and tabulation."""
    settings = VeilgateSettings(policy_path=config)
    loader = PolicyLoader(
        policy_path=config if not from_mcp_json else None,
        from_mcp_json=from_mcp_json,
    )

    async def _catalog() -> None:
        pipeline, db_manager = await create_gateway_pipeline(settings, policy_loader=loader)
        console = Console()

        if shapes:
            async with db_manager.connection() as conn:
                cursor = await conn.execute("SELECT * FROM schema_cache ORDER BY qualified_ref;")
                rows = await cursor.fetchall()

            table = Table(title="Veilgate Observed Schema Shapes & Classifications")
            table.add_column("Qualified Tool", style="cyan")
            table.add_column("Shape Fingerprint", style="magenta")
            table.add_column("Source", style="green")
            table.add_column("Classifications", style="yellow")

            for r in rows:
                table.add_row(r["qualified_ref"], r["shape_fingerprint"][:12], r["source"], r["classifications"])
            console.print(table)
            return

        tools = await pipeline.catalog_repo.list_tools()
        table = Table(title=f"Veilgate Tool Catalog ({len(tools)} tools registered)")
        table.add_column("Qualified Reference", style="cyan", no_wrap=True)
        table.add_column("Server", style="green")
        table.add_column("Capabilities", style="yellow")
        table.add_column("Risk Level", style="magenta")
        table.add_column("Trust", style="blue")
        table.add_column("Status", style="bold")
        table.add_column("Tokens", style="dim", justify="right")

        for t in tools:
            risk_style = "green" if t.risk_level == "LOW" else ("red" if t.risk_level in ("HIGH", "CRITICAL") else "yellow")
            status_style = "green" if t.status == "active" else "red"
            trust_label = "untrusted" if t.untrusted_tool else "trusted"
            table.add_row(
                t.qualified_ref,
                t.server_id,
                ", ".join(t.capabilities) or "read",
                f"[{risk_style}]{t.risk_level}[/{risk_style}]",
                trust_label,
                f"[{status_style}]{t.status}[/{status_style}]",
                str(t.schema_tokens),
            )
        console.print(table)

    asyncio.run(_catalog())


@app.command()
def dashboard(
    port: Annotated[int, typer.Option("--port", "-p", help="Dashboard HTTP port")] = 8765,
    db_path: Annotated[Path, typer.Option("--db", help="Path to SQLite database")] = Path("./veilgate.db"),
) -> None:
    """Launch the Veilgate operator and reviewer dashboard."""
    mgr = DatabaseManager(db_path)
    asyncio.run(mgr.initialize())
    app_instance = create_dashboard_app(mgr)
    typer.echo(f"Starting Veilgate Dashboard on http://localhost:{port}")
    uvicorn.run(app_instance, host="127.0.0.1", port=port, log_level="info")


@app.command()
def bench(
    iterations: Annotated[int, typer.Option("--iterations", "-n", help="Benchmark iterations")] = 100,
    db_path: Annotated[Path, typer.Option("--db", help="Path to benchmark SQLite database")] = Path("./bench.db"),
) -> None:
    """Run catalog discovery and minimization latency benchmarks."""
    settings = VeilgateSettings(db_path=db_path)
    loader = PolicyLoader()
    policy = loader.load()

    async def _run_bench() -> None:
        pipeline, mgr = await create_gateway_pipeline(settings, policy=policy)
        session = SessionContext(session_id="bench_ses")
        await pipeline.sessions.create_or_touch(session.session_id, transport="stdio")

        raw_payload = {
            "invoice_id": 9012,
            "vendor": "Acme Global",
            "contact_email": "finance@acme.example.com",
            "bank_account": "123456789012",
            "routing_number": "021000021",
            "internal_margin": "32.4%",
            "connection": "close",
            "etag": "W/109485",
        }
        ref = ToolRef(server="srv1", tool="get_invoice")

        # Warmup
        await pipeline.minimizer.minimize(raw_payload, ref, session, str(ULID()))

        timings: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            await pipeline.minimizer.minimize(raw_payload, ref, session, str(ULID()))
            timings.append((time.perf_counter() - t0) * 1000.0)

        mean_ms = float(np.mean(timings))
        p95_ms = float(np.percentile(timings, 95))

        console = Console()
        table = Table(title=f"Veilgate Latency Benchmark ({iterations} iterations)")
        table.add_column("Operation", style="cyan")
        table.add_column("Mean Latency", style="green")
        table.add_column("p95 Latency", style="yellow")
        table.add_column("SLA Target", style="magenta")
        table.add_row("Minimizer Egress Pipeline", f"{mean_ms:.2f} ms", f"{p95_ms:.2f} ms", "< 20.00 ms")
        console.print(table)

    asyncio.run(_run_bench())


@app.command()
def run(
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to policy.yaml")] = Path("./policy.yaml"),
    from_mcp_json: Annotated[Path | None, typer.Option("--from-mcp-json", help="Wrap existing mcp.json directly in memory")] = None,
    wrap: Annotated[str | None, typer.Option("--wrap", help="Zero-config wrapper for single stdio command")] = None,
    dev: Annotated[bool, typer.Option("--dev", help="Enable interactive dev mode with learning")] = False,
    transport: Annotated[str, typer.Option("--transport", help="Transport mode: stdio or http")] = "stdio",
    port: Annotated[int, typer.Option("--port", "-p", help="Port for HTTP transport")] = 8765,
    no_jev: Annotated[bool, typer.Option("--no-jev", help="Disable Jev advisory classification")] = False,
) -> None:
    """Start the Veilgate Gateway server."""
    settings = VeilgateSettings(policy_path=config, dev_mode=dev, http_port=port)
    loader = PolicyLoader(
        policy_path=config if not (from_mcp_json or wrap) else None,
        from_mcp_json=from_mcp_json,
    )

    policy = loader.load()

    # Zero-config --wrap mode
    if wrap:
        parts = shlex.split(wrap)
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        wrap_upstream = UpstreamSpec(
            id="wrapped",
            transport=Transport.STDIO,
            command=cmd,
            args=args,
        )
        policy.upstreams = [wrap_upstream]

    if no_jev:
        policy.jev.enabled = False

    async def _start() -> None:
        pipeline, _ = await create_gateway_pipeline(settings, policy=policy, policy_loader=loader)
        server = create_gateway_server(settings, pipeline)

        if transport.lower() == "http":
            typer.echo(f"Starting Veilgate Streamable HTTP Gateway on port {port}...")
            await server.run_async(transport="streamable-http", port=port)
        else:
            await server.run_async(transport="stdio")

    asyncio.run(_start())


if __name__ == "__main__":
    app()
