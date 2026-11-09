from types import SimpleNamespace

import pytest

from lake_mcp.runtime_security import build_auth, network_run_options, secure_dsn
from lake_mcp.safety import SESSION_ID, check_network_sql, check_sql_safety, get_session_prefix


@pytest.mark.parametrize("kind,options", [("TASK", "WAREHOUSE='wh' SCHEDULE=1 MINUTE"), ("PIPE", ""), ("DYNAMIC TABLE", "")])
def test_decoy_literal_cannot_hide_deferred_sql(kind, options):
    for decoy in ["COMMENT='as of now'", 'COMMENT="as quoted"', "COMMENT=$$as quoted$$"]:
        sql = f"CREATE {kind} {get_session_prefix()}t {options} {decoy} AS DROP TABLE production.users"
        assert not check_sql_safety(sql).allowed


def test_required_body_and_session_entropy():
    assert not check_sql_safety(f"CREATE TASK {get_session_prefix()}t").allowed
    assert len(SESSION_ID) == 32


def test_network_requires_actual_mounted_auth(monkeypatch):
    config = SimpleNamespace(mcp_bind_host="0.0.0.0")
    monkeypatch.delenv("LAKE_MCP_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="requires"):
        network_run_options(config, None)
    monkeypatch.setenv("LAKE_MCP_AUTH_TOKEN", "test-network-token-at-least-32-bytes")
    auth = build_auth()
    with pytest.raises(ValueError, match="requires TLS"):
        network_run_options(config, auth)
    monkeypatch.setenv("LAKE_MCP_TRUST_TLS_PROXY", "1")
    assert network_run_options(config, auth)["host"] == "0.0.0.0"
    monkeypatch.setenv("LAKE_MCP_ALLOWED_HOSTS", "*.example.com")
    with pytest.raises(ValueError, match="explicit hosts"):
        network_run_options(config, auth)


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "192.0.2.1", "local.example", " 127.0.0.1 "])
def test_anonymous_network_rejects_non_loopback_hosts(monkeypatch, host):
    monkeypatch.setenv("LAKE_MCP_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(ValueError, match="loopback"):
        network_run_options(SimpleNamespace(mcp_bind_host=host), None)


@pytest.mark.parametrize(("host", "expected"), [("localhost", "127.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("::1", "::1")])
def test_anonymous_network_binds_to_loopback(monkeypatch, host, expected):
    monkeypatch.setenv("LAKE_MCP_ALLOW_INSECURE_HTTP", "true")
    assert network_run_options(SimpleNamespace(mcp_bind_host=host), None)["host"] == expected


@pytest.mark.parametrize(
    "statement",
    [
        "GRANT prod_admin TO {p}user",
        "GRANT ROLE {p}role, prod_admin TO {p}user",
        "REVOKE ROLE {p}role, prod_admin FROM {p}user",
        "GRANT ALL ON {p}db.* TO {p}user, prod_admin, root",
        "REVOKE SELECT ON {p}db.* FROM {p}user, root",
        "GRANT ROLE {p}role TO USER '{p}user'@'%', root",
        "GRANT ROLE {p}role TO ROLE prod_admin",
    ],
)
def test_grant_revoke_blocks_unchecked_names(statement):
    assert not check_sql_safety(statement.format(p=get_session_prefix())).allowed


@pytest.mark.parametrize(
    "statement",
    [
        "GRANT ROLE '{p}role' TO USER '{p}user'@'%'",
        "REVOKE ROLE '{p}role' FROM USER '{p}user'@'%'",
        'GRANT SELECT, INSERT ON "{p}db".* TO ROLE "{p}role"',
        "REVOKE SELECT ON {p}db.* FROM ROLE '{p}role'",
    ],
)
def test_grant_revoke_allows_sandbox_names(statement):
    assert check_sql_safety(statement.format(p=get_session_prefix())).allowed


def test_network_sql_limits_read_only_and_account_administration():
    prefix = get_session_prefix()
    assert check_network_sql("SELECT 1", allow_write=False).allowed
    assert not check_network_sql(f"INSERT INTO {prefix}t VALUES (1)", allow_write=False).allowed
    assert check_network_sql(f"INSERT INTO {prefix}t VALUES (1)", allow_write=True).allowed
    assert not check_network_sql(f"GRANT ROLE {prefix}r TO {prefix}u", allow_write=True).allowed
    assert not check_network_sql(
        f"CREATE TASK {prefix}t AS GRANT ROLE {prefix}r TO {prefix}u", allow_write=True
    ).allowed


def test_safe_mode_does_not_allow_external_code_or_procedure_writes():
    p = get_session_prefix()
    assert check_sql_safety(f"CREATE FUNCTION {p}f AS (x) -> x + 1").allowed
    for statement in (
        f"CREATE FUNCTION {p}f(INT) RETURNS INT LANGUAGE python HANDLER='h' ADDRESS='http://example.invalid/'",
        f"CREATE OR REPLACE FUNCTION {p}f(INT) RETURNS INT LANGUAGE python HANDLER='h' AS $$ code $$",
        f"ALTER FUNCTION {p}f(INT) RETURNS INT LANGUAGE python HANDLER='h' AS $$ code $$",
        f"CREATE PROCEDURE {p}p() RETURNS INT LANGUAGE SQL AS $$ BEGIN DROP DATABASE production; END $$",
    ):
        assert not check_sql_safety(statement).allowed


def test_warehouse_dsn_requires_tls_for_remote_hosts():
    assert "sslmode=require" in secure_dsn("lake://warehouse.example/db")
    assert "sslmode=disable" in secure_dsn("http://127.0.0.1:8000/db?sslmode=disable")
    with pytest.raises(ValueError, match="Plaintext"):
        secure_dsn("lake://warehouse.example/db?SSLMODE=disable")


def test_sql_and_driver_errors_do_not_reach_logs(monkeypatch, caplog):
    from lake_mcp import server

    monkeypatch.setattr(server, "get_config", lambda: SimpleNamespace(safe_mode=True, query_timeout=1))

    def fail(_sql):
        raise RuntimeError("driver-private-error")

    monkeypatch.setattr(server, "execute_lake_query", fail)
    assert server._execute_sql("SELECT 'sql-private-value'")["status"] == "error"
    assert "sql-private-value" not in caplog.text
    assert "driver-private-error" not in caplog.text
