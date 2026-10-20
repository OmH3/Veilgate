import json
import re
from pathlib import Path
from typing import Any

import yaml

from veilgate.config.policy_models import (
    ArgGuardRuleSpec,
    DetectorSpec,
    FieldAction,
    FieldRuleSpec,
    LearnedGrant,
    SensitiveKeyRuleSpec,
    ServerProfileRuleSpec,
    TokenizeSpec,
    ToolPolicySpec,
    Transport,
    UpstreamSpec,
    VeilgatePolicy,
    VerbRuleSpec,
)
from veilgate.exceptions.types import ConfigError
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.config.policy_loader")

PACKS_DIR: Path = Path(__file__).parent.parent / "packs"


def load_yaml_file(path: Path) -> dict[str, Any]:
    """Safely parse a YAML file into a dictionary.

    Args:
        path: Path to YAML file.

    Returns:
        Parsed dictionary content.

    Raises:
        ConfigError: If file cannot be read or contains invalid YAML syntax.
    """
    try:
        if not path.exists():
            return {}
        with open(path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
            if content is None:
                return {}
            if not isinstance(content, dict):
                raise ConfigError(
                    safe_message=f"YAML file '{path.name}' must contain a top-level mapping.",
                    details={"file": str(path)},
                )
            return content
    except yaml.YAMLError as e:
        raise ConfigError(
            safe_message=f"Malformed YAML syntax in '{path.name}': {e}",
            details={"file": str(path)},
        ) from e
    except OSError as e:
        raise ConfigError(
            safe_message=f"Failed to read file '{path.name}': {e}",
            details={"file": str(path)},
        ) from e


def load_mcp_json(path: Path) -> list[UpstreamSpec]:
    """Parse client mcp.json configuration into UpstreamSpec objects."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ConfigError(
            safe_message=f"Failed to read mcp.json at '{path}': {e}",
            details={"file": str(path)},
        ) from e

    servers = data.get("mcpServers", {})
    upstreams: list[UpstreamSpec] = []
    for srv_id, srv_def in servers.items():
        if srv_id.lower() == "veilgate":
            continue
        clean_id = re.sub(r"[^a-z0-9]", "", srv_id.lower())
        if not clean_id:
            clean_id = "upstream"
        if not clean_id[0].isalpha():
            clean_id = "s" + clean_id
        clean_id = clean_id[:24]

        upstreams.append(
            UpstreamSpec(
                id=clean_id,
                transport=Transport.STDIO,
                command=srv_def.get("command", "python"),
                args=srv_def.get("args", []),
                env=srv_def.get("env", {}),
            )
        )
    return upstreams


class PolicyLoader:
    """Manages loading, validation, compilation, and live reloading of Veilgate policies."""

    def __init__(
        self,
        policy_path: Path | None = None,
        learned_policy_path: Path | None = None,
        from_mcp_json: Path | None = None,
        packs_dir: Path | None = None,
    ) -> None:
        self.policy_path: Path | None = policy_path
        self.learned_policy_path: Path | None = learned_policy_path or (
            policy_path.parent / "policy.learned.yaml" if policy_path else None
        )
        self.from_mcp_json_path: Path | None = from_mcp_json
        self.packs_dir: Path = packs_dir or PACKS_DIR
        self._cached_policy: VeilgatePolicy | None = None

    def load(self, force_reload: bool = False) -> VeilgatePolicy:
        """Load, compile, and validate the 3-layer policy hierarchy.

        Order of Precedence:
            Layer 1: User explicit overrides in policy.yaml
            Layer 2: Interactive grants in policy.learned.yaml
            Layer 3: Declarative rule packs in packs/*.yaml
        """
        if self._cached_policy is not None and not force_reload:
            return self._cached_policy

        # Zero-file MCP JSON mode: synthesize policy from mcp.json
        if self.from_mcp_json_path:
            upstreams = load_mcp_json(self.from_mcp_json_path)
            policy = VeilgatePolicy(
                version="1",
                extends="recommended",
                upstreams=upstreams,
            )
            self._compile_flat_keywords(policy)
            self._load_packs(policy)
            self._cached_policy = policy
            logger.info(
                f"SUCCESS | Policy synthesized in-memory from {self.from_mcp_json_path.name} "
                f"with {len(policy.upstreams)} upstreams"
            )
            return policy

        user_raw = load_yaml_file(self.policy_path) if self.policy_path else {}
        learned_raw = load_yaml_file(self.learned_policy_path) if self.learned_policy_path else {}

        # Merge learned grants into user config structure
        learned_grants_data: list[dict[str, str]] = []
        if "grants" in learned_raw and isinstance(learned_raw["grants"], list):
            learned_grants_data = learned_raw["grants"]

        merged_data = dict(user_raw)
        if learned_grants_data:
            merged_data["learned_grants"] = learned_grants_data

        try:
            policy = VeilgatePolicy.model_validate(merged_data)
        except Exception as e:
            raise ConfigError(
                safe_message=f"Policy validation failed: {e}",
                details={"policy_path": str(self.policy_path)},
            ) from e

        # Compile flat protect/drop keywords into deep wildcard JSONPath rules
        self._compile_flat_keywords(policy)

        # Compile rule packs from packs/*.yaml
        self._load_packs(policy)

        self._cached_policy = policy
        source_name = self.policy_path.name if self.policy_path else "in-memory"
        logger.info(
            f"SUCCESS | Policy compiled successfully from {source_name} "
            f"with {len(policy.upstreams)} upstreams, {len(policy.tools)} tool overrides, "
            f"and {len(policy.loaded_detectors)} active PII detectors"
        )
        return policy

    def _compile_flat_keywords(self, policy: VeilgatePolicy) -> None:
        """Expand flat protect and drop keyword lists into synthetic field rules."""
        synthetic_field_rules: list[FieldRuleSpec] = []

        for keyword in policy.protect:
            clean_kw = keyword.strip()
            if not clean_kw:
                continue
            synthetic_field_rules.append(
                FieldRuleSpec(
                    path=f"$..{clean_kw}",
                    action=FieldAction.TOKENIZE,
                    tokenize=TokenizeSpec(
                        token_type=clean_kw.upper(),
                        allowed_sinks="trusted_read",
                        allow_external_egress=False,
                    ),
                )
            )

        for keyword in policy.drop:
            clean_kw = keyword.strip()
            if not clean_kw:
                continue
            synthetic_field_rules.append(
                FieldRuleSpec(
                    path=f"$..{clean_kw}",
                    action=FieldAction.DROP,
                )
            )

        if synthetic_field_rules:
            global_tool_spec = ToolPolicySpec(
                match="*.*",
                allow=True,
                field_rules=synthetic_field_rules,
            )
            policy.tools.append(global_tool_spec)

    def _load_packs(self, policy: VeilgatePolicy) -> None:
        """Dynamically load and compile all declarative YAML rule packs."""
        if not self.packs_dir.exists():
            return

        for pack_file in self.packs_dir.glob("*.yaml"):
            pack_data = load_yaml_file(pack_file)
            if not pack_data:
                continue

            # 1. PII detectors (pii-global, pii-india)
            if "detectors" in pack_data and isinstance(pack_data["detectors"], list):
                for d in pack_data["detectors"]:
                    try:
                        policy.loaded_detectors.append(DetectorSpec.model_validate(d))
                    except Exception as e:
                        logger.warning(f"Failed to parse detector {d.get('id')} in {pack_file.name}: {e}")

            # 2. Sensitive key stems (sensitive-keys)
            if "rules" in pack_data and isinstance(pack_data["rules"], list):
                for r in pack_data["rules"]:
                    if "stems" in r:
                        try:
                            policy.loaded_sensitive_keys.append(SensitiveKeyRuleSpec.model_validate(r))
                        except Exception as e:
                            logger.warning(f"Failed to parse sensitive key rule in {pack_file.name}: {e}")
                    elif "capability" in r:
                        # 4. Verb rules (core-verbs)
                        try:
                            policy.loaded_verb_rules.append(VerbRuleSpec.model_validate(r))
                        except Exception as e:
                            logger.warning(f"Failed to parse verb rule in {pack_file.name}: {e}")
                    elif "trust" in r:
                        # 5. Server profiles (server-profiles)
                        try:
                            policy.loaded_server_profiles.append(ServerProfileRuleSpec.model_validate(r))
                        except Exception as e:
                            logger.warning(f"Failed to parse server profile in {pack_file.name}: {e}")

            # 3. Bloat HTTP keys (bloat-http)
            if "drop_keys" in pack_data and isinstance(pack_data["drop_keys"], list):
                for k in pack_data["drop_keys"]:
                    policy.loaded_bloat_keys.add(k.lower())

            # 6. Argument guards (arg-guards)
            if "guards" in pack_data and isinstance(pack_data["guards"], list):
                for g in pack_data["guards"]:
                    try:
                        policy.loaded_arg_guards.append(ArgGuardRuleSpec.model_validate(g))
                    except Exception as e:
                        logger.warning(f"Failed to parse arg guard in {pack_file.name}: {e}")

    def append_learned_grant(self, grant: LearnedGrant) -> None:
        """Append an interactive dev grant to policy.learned.yaml and trigger hot reload."""
        try:
            learned_raw = load_yaml_file(self.learned_policy_path)
            grants_list: list[dict[str, str]] = learned_raw.get("grants", [])
            grants_list.append(grant.model_dump())
            learned_raw["grants"] = grants_list

            with open(self.learned_policy_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(learned_raw, f, sort_keys=False)

            # Hot-reload policy into memory
            self.load(force_reload=True)
            logger.info(f"SUCCESS | Learned grant {grant.grant_id} appended and policy hot-reloaded")
        except OSError as e:
            raise ConfigError(
                safe_message=f"Failed to persist learned grant to '{self.learned_policy_path.name}': {e}",
                details={"file": str(self.learned_policy_path)},
            ) from e

    def promote_learned_grants(self) -> int:
        """Promote all grants in policy.learned.yaml into policy.yaml tool rules."""
        if not self.policy_path or not self.learned_policy_path or not self.learned_policy_path.exists():
            return 0

        learned_raw = load_yaml_file(self.learned_policy_path)
        grants: list[dict[str, str]] = learned_raw.get("grants", [])
        if not grants:
            return 0

        user_raw = load_yaml_file(self.policy_path)
        tools_list: list[dict[str, Any]] = user_raw.get("tools", [])

        promoted_count = 0
        for grant in grants:
            pattern = grant.get("pattern", "")
            if not pattern:
                continue
            # Add or update tool rule
            tools_list.append({
                "match": pattern,
                "allow": True,
                "require_approval": False,
            })
            promoted_count += 1

        user_raw["tools"] = tools_list
        with open(self.policy_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(user_raw, f, sort_keys=False)

        # Clear learned policy file
        with open(self.learned_policy_path, "w", encoding="utf-8") as f:
            yaml.safe_dump({"grants": []}, f)

        self.load(force_reload=True)
        logger.info(f"SUCCESS | Promoted {promoted_count} learned grants into {self.policy_path.name}")
        return promoted_count

