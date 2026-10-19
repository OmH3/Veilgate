"""Unit tests for Veilgate runtime settings."""

from pathlib import Path

from veilgate.config.settings import VeilgateSettings


def test_default_settings_instantiation() -> None:
    """Verify default runtime settings instantiate correctly."""
    settings = VeilgateSettings()
    assert settings.db_path == Path("./veilgate.db")
    assert settings.log_level == "INFO"
    assert settings.dashboard_port == 7878
    assert settings.http_port == 8765
    assert settings.upstream_timeout_seconds == 30.0
    assert settings.token_ttl_seconds == 86_400
    assert settings.dev_mode is False


def test_env_override(monkeypatch) -> None:
    """Verify environment variable prefix VEILGATE_ overrides defaults."""
    monkeypatch.setenv("VEILGATE_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("VEILGATE_DASHBOARD_PORT", "9090")
    monkeypatch.setenv("VEILGATE_DEV_MODE", "true")
    monkeypatch.setenv("JEV_API_KEY", "test-jev-key")

    settings = VeilgateSettings()
    assert settings.log_level == "DEBUG"
    assert settings.dashboard_port == 9090
    assert settings.dev_mode is True
    assert settings.jev_api_key is not None
    assert settings.jev_api_key.get_secret_value() == "test-jev-key"
