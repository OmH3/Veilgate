"""Environment and operational runtime settings for Veilgate Gateway."""

from pathlib import Path
from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class VeilgateSettings(BaseSettings):
    """Runtime configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_prefix="VEILGATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: Path = Field(
        default=Path("./veilgate.db"),
        description="Path to SQLite database file.",
    )
    log_level: str = Field(
        default="INFO",
        description="Standard logging severity level (DEBUG, INFO, WARNING, ERROR).",
    )
    master_key: SecretStr | None = Field(
        default=None,
        description="Base64-encoded 32-byte master key for AES-256-GCM token encryption.",
    )
    policy_path: Path = Field(
        default=Path("./policy.yaml"),
        description="Primary user-defined declarative policy file.",
    )
    learned_policy_path: Path = Field(
        default=Path("./policy.learned.yaml"),
        description="Secondary file for interactive grants learned during development.",
    )
    dashboard_port: int = Field(
        default=7878,
        description="Port for the FastAPI dashboard and HITL review modal.",
    )
    http_port: int = Field(
        default=8765,
        description="Port for streamable HTTP MCP transport.",
    )
    upstream_timeout_seconds: float = Field(
        default=30.0,
        description="Maximum seconds to wait for an upstream MCP server response.",
    )
    approval_timeout_seconds: int = Field(
        default=120,
        description="Maximum seconds to wait for human-in-the-loop review decision.",
    )
    token_ttl_seconds: int = Field(
        default=86_400,
        description="Token time-to-live in seconds (default 24h).",
    )
    stash_ttl_seconds: int = Field(
        default=1_800,
        description="Dropped non-sensitive payload stash TTL in seconds (default 30m).",
    )

    @model_validator(mode="after")
    def _resolve_canonical_paths(self) -> Self:
        """Canonically anchor db_path and learned_policy_path next to the policy file.

        Prevents cwd-dependent state divergence when Veilgate is spawned by IDEs
        or MCP clients running in arbitrary working directories.
        """
        resolved_policy = self.policy_path.resolve()
        if self.policy_path.exists():
            self.policy_path = resolved_policy

        if self.db_path == Path("./veilgate.db") or self.db_path is None:
            if resolved_policy.exists() or resolved_policy.parent.exists():
                self.db_path = resolved_policy.parent / "veilgate.db"
            else:
                self.db_path = Path.home() / ".veilgate" / "veilgate.db"
        else:
            self.db_path = self.db_path.resolve()

        if self.learned_policy_path == Path("./policy.learned.yaml") or self.learned_policy_path is None:
            self.learned_policy_path = resolved_policy.parent / "policy.learned.yaml"
        else:
            self.learned_policy_path = self.learned_policy_path.resolve()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        return self
