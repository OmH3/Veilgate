"""Environment and operational runtime settings for Veilgate Gateway."""

from pathlib import Path
from pydantic import Field, SecretStr
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
    dev_mode: bool = Field(
        default=False,
        description="Interactive development mode with live elicitation prompts and learning.",
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
    jev_api_key: SecretStr | None = Field(
        default=None,
        alias="JEV_API_KEY",
        description="Optional API key for Jev probabilistic shape classification.",
    )
    jev_base_url: str = Field(
        default="https://jevmodel.net",
        alias="JEV_BASE_URL",
        description="Base URL for Jev inference endpoint.",
    )
