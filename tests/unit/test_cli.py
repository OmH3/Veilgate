"""Unit tests for Veilgate CLI commands."""

import json
from pathlib import Path
from typer.testing import CliRunner

from veilgate.cli import app

runner = CliRunner()


def test_cli_keygen() -> None:
    """Verify veilgate keygen generates a 32-byte base64 master key."""
    result = runner.invoke(app, ["keygen"])
    assert result.exit_code == 0
    assert "Master key generated" in result.stdout


def test_cli_validate_valid_and_invalid(tmp_path: Path) -> None:
    """Verify veilgate validate on valid and broken policy files."""
    valid_file = tmp_path / "valid.yaml"
    valid_file.write_text("version: '1'\nextends: recommended\n", encoding="utf-8")

    res_valid = runner.invoke(app, ["validate", "--config", str(valid_file)])
    assert res_valid.exit_code == 0
    assert "is valid" in res_valid.stdout

    broken_file = tmp_path / "broken.yaml"
    broken_file.write_text("upstreams: [unclosed", encoding="utf-8")

    res_broken = runner.invoke(app, ["validate", "--config", str(broken_file)])
    assert res_broken.exit_code != 0


def test_cli_explain_tool(tmp_path: Path) -> None:
    """Verify veilgate explain returns JSON explanation for tool."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: '1'\n", encoding="utf-8")

    result = runner.invoke(app, ["explain", "invoicedb.get_invoice", "--config", str(policy_file)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["tool"] == "invoicedb.get_invoice"
    assert "capabilities" in data


def test_cli_explain_payload(tmp_path: Path) -> None:
    """Verify veilgate explain explains dictionary payload fields."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: '1'\n", encoding="utf-8")

    payload_json = json.dumps({"bank_routing": "021000021", "x-powered-by": "express"})
    result = runner.invoke(app, ["explain", payload_json, "--config", str(policy_file)])
    assert result.exit_code == 0
    explanations = json.loads(result.stdout)
    paths = [e["path"] for e in explanations]
    actions = [e["action"] for e in explanations]
    assert "$.bank_routing" in paths
    assert "$.x-powered-by" in paths
    assert "TOKENIZE" in actions
    assert "DROP" in actions


def test_cli_adopt(tmp_path: Path) -> None:
    """Verify veilgate adopt imports mcp.json, creates policy.yaml, and reconfigures client."""
    mcp_json_path = tmp_path / "mcp.json"
    client_config = {
        "mcpServers": {
            "sqlite": {
                "command": "python",
                "args": ["server.py"],
            }
        }
    }
    mcp_json_path.write_text(json.dumps(client_config), encoding="utf-8")
    output_policy = tmp_path / "adopted_policy.yaml"

    result = runner.invoke(app, ["adopt", "--mcp-json", str(mcp_json_path), "-o", str(output_policy)])
    assert result.exit_code == 0
    assert output_policy.exists()

    # Verify backup exists
    bak_path = mcp_json_path.with_suffix(".veilgate.bak.json")
    assert bak_path.exists()

    # Verify rewired mcp.json
    rewired = json.loads(mcp_json_path.read_text(encoding="utf-8"))
    assert "veilgate" in rewired["mcpServers"]


def test_cli_catalog_and_from_mcp_json(tmp_path: Path) -> None:
    """Verify veilgate catalog and --from-mcp-json flag."""
    mcp_json_path = tmp_path / "test_client_mcp.json"
    mcp_json_path.write_text(
        json.dumps({
            "mcpServers": {
                "invoicedb": {
                    "command": "python",
                    "args": ["server.py"],
                }
            }
        }),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["catalog", "--from-mcp-json", str(mcp_json_path)])
    assert result.exit_code == 0
    assert "Veilgate Tool Catalog" in result.stdout
