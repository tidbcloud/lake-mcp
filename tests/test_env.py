"""Tests for environment configuration."""

from lake_mcp.env import LakeMCPConfig


def test_safe_mode_defaults_to_enabled(monkeypatch):
    monkeypatch.delenv("LAKE_MCP_SAFE_MODE", raising=False)

    assert LakeMCPConfig().safe_mode is True


def test_safe_mode_falsey_values(monkeypatch):
    for value in ["false", "0", "no", "off"]:
        monkeypatch.setenv("LAKE_MCP_SAFE_MODE", value)

        assert LakeMCPConfig().safe_mode is False


def test_safe_mode_rejects_invalid_value(monkeypatch):
    monkeypatch.setenv("LAKE_MCP_SAFE_MODE", "flase")

    try:
        LakeMCPConfig().safe_mode
    except ValueError as err:
        assert "LAKE_MCP_SAFE_MODE" in str(err)
    else:
        raise AssertionError("Expected ValueError")


def test_safe_mode_truthy_values(monkeypatch):
    for value in ["true", "1", "yes", "on"]:
        monkeypatch.setenv("LAKE_MCP_SAFE_MODE", value)

        assert LakeMCPConfig().safe_mode is True
