"""End-to-End Test for MCP Stdio Transport Purity.

Asserts that when the Veilgate Gateway server runs in standard stdio mode:
1. Every single line emitted to stdout is a 100% valid, parseable JSON-RPC frame.
2. Zero application logs, debug messages, warnings, or stray prints leak to stdout.
3. All structured operational and security logging is routed strictly to stderr.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import pytest
import yaml


def test_stdio_transport_purity(tmp_path: Path) -> None:
    """Spawn veilgate gateway via stdio and verify zero log leakage to stdout."""
    db_file = tmp_path / "veilgate_purity.db"
    policy_file = tmp_path / "policy.yaml"

    # Write minimal policy with search diet mode enabled
    policy_data = {
        "version": "1",
        "extends": "minimal",
        "default_tool_allow": True,
        "upstreams": [],
        "diet": {
            "mode": "search",
        },
    }
    with open(policy_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(policy_data, f)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["VEILGATE_DB_PATH"] = str(db_file.resolve())

    cmd = [
        sys.executable,
        "-m",
        "veilgate.cli",
        "run",
        "--config",
        str(policy_file.resolve()),
        "--transport",
        "stdio",
    ]

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
        bufsize=1,
    )

    try:
        # 1. Send MCP initialize JSON-RPC request
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "purity-tester",
                    "version": "1.0.0",
                },
            },
        }
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None

        process.stdin.write(json.dumps(init_req) + "\n")
        process.stdin.flush()

        # 2. Read first response line from stdout
        init_response_raw = process.stdout.readline()
        assert init_response_raw, "Gateway closed stdout without sending initialize response"

        # Purity check: must parse as valid JSON
        init_response = json.loads(init_response_raw.strip())
        assert init_response.get("jsonrpc") == "2.0"
        assert init_response.get("id") == 1
        assert "result" in init_response
        assert "serverInfo" in init_response["result"]
        assert init_response["result"]["serverInfo"]["name"] == "Veilgate"

        # 3. Send initialized notification
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        process.stdin.write(json.dumps(notif) + "\n")
        process.stdin.flush()

        # 4. Send tools/list request
        list_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        process.stdin.write(json.dumps(list_req) + "\n")
        process.stdin.flush()

        # 5. Read tools/list response line
        list_response_raw = process.stdout.readline()
        assert list_response_raw, "Gateway closed stdout without sending tools/list response"

        # Purity check: must parse as valid JSON
        list_response = json.loads(list_response_raw.strip())
        assert list_response.get("jsonrpc") == "2.0"
        assert list_response.get("id") == 2
        assert "result" in list_response
        assert "tools" in list_response["result"]

        # Meta-tools veilgate_search_tools and veilgate_expand should be present
        tool_names = [t["name"] for t in list_response["result"]["tools"]]
        assert "veilgate_search_tools" in tool_names
        assert "veilgate_expand" in tool_names

        # 6. Send tools/call request for veilgate_search_tools
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "veilgate_search_tools",
                "arguments": {"query": "invoice"},
            },
        }
        process.stdin.write(json.dumps(call_req) + "\n")
        process.stdin.flush()

        # Read tools/call response line
        call_response_raw = process.stdout.readline()
        assert call_response_raw, "Gateway closed stdout without sending tools/call response"

        # Purity check: must parse as valid JSON
        call_response = json.loads(call_response_raw.strip())
        assert call_response.get("jsonrpc") == "2.0"
        assert call_response.get("id") == 3
        assert "result" in call_response
        assert "content" in call_response["result"]

    finally:
        # Graceful shutdown: close stdin then terminate
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        except OSError:
            pass

        try:
            process.terminate()
            stdout_rem, stderr_rem = process.communicate(timeout=5)
        except Exception:
            process.kill()
            stdout_rem, stderr_rem = process.communicate()

    # 6. Strict Assertion: Every single non-empty line received on stdout was valid JSON
    if stdout_rem:
        for line in stdout_rem.strip().splitlines():
            line_str = line.strip()
            if line_str:
                # Will raise ValueError if any stray log leaked into stdout
                parsed = json.loads(line_str)
                assert "jsonrpc" in parsed or "method" in parsed

    # 7. Verification that logging took place on stderr, not stdout
    assert stderr_rem, "Expected structured logs on stderr during gateway startup and execution"
    assert "veilgate" in stderr_rem.lower()
