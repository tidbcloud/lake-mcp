"""Explicit local configuration and optional HTTP bearer authentication."""

import os
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv


def load_config_file():
    # Never search parent directories: an unrelated ancestor .env is not policy.
    path = os.environ.get("LAKE_MCP_ENV_FILE")
    if path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            raise ValueError("LAKE_MCP_ENV_FILE must be an absolute path")
        if not candidate.is_file():
            raise ValueError("LAKE_MCP_ENV_FILE must name an existing file")
        load_dotenv(candidate, override=False)


def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def secure_dsn(dsn):
    """Require an explicit warehouse DSN and TLS off the local loopback."""
    try:
        parts = urlsplit(dsn)
        if parts.scheme not in {"lake", "databend", "http", "https"} or not parts.hostname:
            raise ValueError
        query = parse_qsl(parts.query, keep_blank_values=True)
        modes = [value for key, value in query if key.lower() == "sslmode"]
        if len(modes) > 1 or (modes and modes[0] not in {"require", "disable"}):
            raise ValueError
    except ValueError:
        raise ValueError("Invalid LAKE_DSN or sslmode") from None
    mode = modes[0] if modes else "require"
    if (mode == "disable" and not _is_loopback(parts.hostname)) or (parts.scheme == "http" and mode != "disable"):
        raise ValueError("Plaintext LAKE_DSN requires loopback and explicit sslmode=disable")
    query = [(key, value) for key, value in query if key.lower() != "sslmode"]
    return urlunsplit(parts._replace(query=urlencode([*query, ("sslmode", mode)])))


def build_auth():
    from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier

    token = os.environ.get("LAKE_MCP_AUTH_TOKEN")
    jwks = os.environ.get("LAKE_MCP_AUTH_JWKS_URI")
    issuer = os.environ.get("LAKE_MCP_AUTH_ISSUER")
    audience = os.environ.get("LAKE_MCP_AUTH_AUDIENCE")
    subject = os.environ.get("LAKE_MCP_AUTH_SUBJECT")
    if any((jwks, issuer, audience, subject)):
        if token is not None or not all((jwks, issuer, audience, subject)):
            raise ValueError("Configure a static token or a complete JWT issuer, audience, subject and JWKS URI")
        if urlsplit(jwks).scheme != "https" or not urlsplit(jwks).hostname:
            raise ValueError("LAKE_MCP_AUTH_JWKS_URI must be an HTTPS URL")

        class ExpiringJWTVerifier(JWTVerifier):
            async def verify_token(self, value):
                verified = await super().verify_token(value)
                if verified is None or verified.expires_at is None or (verified.claims or {}).get("sub") != subject:
                    return None
                return verified

        return ExpiringJWTVerifier(jwks_uri=jwks, issuer=issuer, audience=audience, required_scopes=["lake"])
    required = os.environ.get("LAKE_MCP_REQUIRE_AUTH", "false").lower()
    if required not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("Invalid LAKE_MCP_REQUIRE_AUTH; use true or false")
    if token is not None and (len(token.encode()) < 32 or token != token.strip()):
        raise ValueError("LAKE_MCP_AUTH_TOKEN must be at least 32 bytes without surrounding whitespace")
    if required in {"true", "1", "yes", "on"} and not token:
        raise ValueError("LAKE_MCP_REQUIRE_AUTH requires LAKE_MCP_AUTH_TOKEN")
    if not token:
        return None
    return StaticTokenVerifier(tokens={token: {"client_id": "lake-mcp", "scopes": ["lake", "lake:write"]}}, required_scopes=["lake"])


def network_run_options(config, auth):
    """Validate the actual mounted authenticator before opening a listener."""
    from starlette.middleware import Middleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    insecure = os.environ.get("LAKE_MCP_ALLOW_INSECURE_HTTP", "false").strip().lower()
    if insecure not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("Invalid LAKE_MCP_ALLOW_INSECURE_HTTP; use true or false")
    if auth is None and insecure not in {"true", "1", "yes", "on"}:
        raise ValueError(
            "HTTP/SSE requires configured authentication; local development may explicitly set LAKE_MCP_ALLOW_INSECURE_HTTP=true"
        )
    host = config.mcp_bind_host
    loopback = _is_loopback(host)
    if auth is None:
        if not loopback:
            raise ValueError("Anonymous HTTP/SSE requires a loopback LAKE_MCP_BIND_HOST")
        if host == "localhost":
            host = "127.0.0.1"

    cert = os.environ.get("LAKE_MCP_TLS_CERTFILE")
    key = os.environ.get("LAKE_MCP_TLS_KEYFILE")
    if bool(cert) != bool(key) or (cert and not (Path(cert).is_file() and Path(key).is_file())):
        raise ValueError("LAKE_MCP_TLS_CERTFILE and LAKE_MCP_TLS_KEYFILE must name existing files")
    if not loopback and not cert and os.environ.get("LAKE_MCP_TRUST_TLS_PROXY") != "1":
        raise ValueError("Non-loopback HTTP/SSE requires TLS files or LAKE_MCP_TRUST_TLS_PROXY=1")

    hosts = [h.strip() for h in os.environ.get("LAKE_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",") if h.strip()]
    if not hosts or any("*" in h for h in hosts):
        raise ValueError("LAKE_MCP_ALLOWED_HOSTS must list explicit hosts")
    options = {"host": host, "middleware": [Middleware(TrustedHostMiddleware, allowed_hosts=hosts)]}
    if cert:
        options["uvicorn_config"] = {"ssl_certfile": cert, "ssl_keyfile": key}
    return options
