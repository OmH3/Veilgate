"""Unit tests for PolicyLoader 3-layer compilation and auto-expansion."""

from pathlib import Path

import pytest

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import FieldAction, LearnedGrant
from veilgate.exceptions.types import ConfigError


def test_load_non_existent_policy_returns_default(tmp_path: Path) -> None:
    """Verify loading non-existent policy.yaml yields clean default policy."""
    policy_file = tmp_path / "policy.yaml"
    loader = PolicyLoader(policy_path=policy_file)
    policy = loader.load()

    assert policy.version == "1"
    assert policy.extends == "recommended"
    assert policy.default_tool_allow is True
    assert len(policy.upstreams) == 0


def test_compile_flat_keywords_into_deep_wildcards(tmp_path: Path) -> None:
    """Verify flat protect and drop lists expand to deep synthetic field rules."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
version: "1"
upstreams:
  - id: invoicedb
    transport: stdio
    command: python
protect:
  - deal_margin
  - ssn_backup
drop:
  - internal_uuid
""",
        encoding="utf-8",
    )

    loader = PolicyLoader(policy_path=policy_file)
    policy = loader.load()

    assert len(policy.upstreams) == 1
    # Check synthetic tool rule was created
    synthetic_tool = next((t for t in policy.tools if t.match == "*.*"), None)
    assert synthetic_tool is not None
    assert len(synthetic_tool.field_rules) == 3

    paths = [r.path for r in synthetic_tool.field_rules]
    actions = [r.action for r in synthetic_tool.field_rules]
    assert "$..deal_margin" in paths
    assert "$..ssn_backup" in paths
    assert "$..internal_uuid" in paths
    assert FieldAction.TOKENIZE in actions
    assert FieldAction.DROP in actions


def test_learned_grant_append_and_hot_reload(tmp_path: Path) -> None:
    """Verify learned grant persistence to policy.learned.yaml and immediate reload."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: '1'\n", encoding="utf-8")
    learned_file = tmp_path / "policy.learned.yaml"

    loader = PolicyLoader(policy_path=policy_file, learned_policy_path=learned_file)
    initial_policy = loader.load()
    assert len(initial_policy.learned_grants) == 0

    grant = LearnedGrant(
        grant_id="grnt_01JAB",
        pattern="invoicedb.compare_*:account",
        token_type="BANK_ROUTING",
        created_at="2026-10-19T10:00:00Z",
    )
    loader.append_learned_grant(grant)

    reloaded_policy = loader.load()
    assert len(reloaded_policy.learned_grants) == 1
    assert reloaded_policy.learned_grants[0].grant_id == "grnt_01JAB"
    assert reloaded_policy.learned_grants[0].token_type == "BANK_ROUTING"


def test_malformed_yaml_raises_config_error(tmp_path: Path) -> None:
    """Verify broken YAML syntax raises ConfigError."""
    policy_file = tmp_path / "broken.yaml"
    policy_file.write_text("version: [unclosed list", encoding="utf-8")

    loader = PolicyLoader(policy_path=policy_file)
    with pytest.raises(ConfigError):
        loader.load()
