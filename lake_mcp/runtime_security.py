"""Explicit local configuration and optional HTTP bearer authentication."""

import json
import os
import secrets
import stat
from contextlib import contextmanager
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from fastmcp.server.dependencies import get_http_request
from starlette.responses import PlainTextResponse


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


def _unique_subjects(pairs):
    entries = dict(pairs)
    if len(entries) != len(pairs):
        raise ValueError("Duplicate subject in warehouse map")
    return entries


@contextmanager
def _open_private_file(path):
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("Credential files must use absolute paths")
    fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or (os.name == "posix" and (info.st_mode & 0o077 or info.st_uid not in {os.geteuid(), 0})):
            raise ValueError("Credential files must be private regular files owned by the service or root")
        yield stream


def _read_private_file(path):
    with _open_private_file(path) as stream:
        return stream.read()


def _load_warehouse_dsns(path):
    try:
        entries = json.loads(_read_private_file(path), object_pairs_hook=_unique_subjects)
        if not isinstance(entries, dict) or not entries:
            raise ValueError
        dsns = {}
        accounts = set()
        credential_files = set()
        for subject, dsn in entries.items():
            if not subject or not isinstance(dsn, str):
                raise ValueError
            dsn = secure_dsn(dsn)
            parts = urlsplit(dsn)
            query = parse_qsl(parts.query, keep_blank_values=True)
            if ("sslmode", "require") not in query or any(key.lower() == "access_token" for key, _ in query):
                raise ValueError
            keys = [value for key, value in query if key in {"access_token_file", "private_key_file"}]
            passphrases = [value for key, value in query if key == "private_key_passphrase_file"]
            if len(keys) > 1 or len(passphrases) > 1 or (passphrases and not any(key == "private_key_file" for key, _ in query)):
                raise ValueError
            if keys:
                if parts.password or (not parts.username and any(key == "private_key_file" for key, _ in query)):
                    raise ValueError
                for filename in keys + passphrases:
                    with _open_private_file(filename):
                        pass
                credential_file = Path(keys[0]).resolve()
                if credential_file in credential_files:
                    raise ValueError
                credential_files.add(credential_file)
            elif not parts.username or not parts.password:
                raise ValueError
            tenants = [value for key, value in query if key == "tenant"]
            if len(tenants) > 1:
                raise ValueError
            if parts.username:
                account = (parts.hostname.rstrip("."), parts.port or 443, tenants[0] if tenants else "", unquote(parts.username))
                if account in accounts:
                    raise ValueError
                accounts.add(account)
            dsns[subject] = dsn
        return dsns
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Invalid warehouse map: expected private files and separate TLS Lake accounts") from None


def _read_bearer_token(path):
    value = _read_private_file(path).rstrip("\r\n")
    if len(value.encode()) < 32 or value != value.strip():
        raise ValueError("Bearer token file must contain at least 32 bytes without surrounding whitespace")
    return value


class FileTokenVerifier(TokenVerifier):
    def __init__(self, path):
        super().__init__(required_scopes=["lake"])
        self._path = path
        _read_bearer_token(path)

    async def verify_token(self, value):
        try:
            expected = _read_bearer_token(self._path)
        except (OSError, ValueError):
            return None
        if not secrets.compare_digest(value.encode(), expected.encode()):
            return None
        return AccessToken(token=value, client_id="lake-mcp", scopes=["lake", "lake:write"])


class LakeJWTVerifier(JWTVerifier):
    def __init__(self, *, subject=None, warehouse_map=None, **kwargs):
        super().__init__(**kwargs)
        self._subject = subject
        self._warehouse_map = warehouse_map
        if warehouse_map is not None:
            _load_warehouse_dsns(warehouse_map)

    @property
    def routes_warehouse_accounts(self):
        return self._warehouse_map is not None

    def warehouse_dsn(self, token):
        if token is None or self._warehouse_map is None:
            return None
        return self._dsn_for_subject(token.subject)

    def _dsn_for_subject(self, subject):
        try:
            return _load_warehouse_dsns(self._warehouse_map).get(subject)
        except ValueError:
            return None

    async def verify_token(self, value):
        verified = await super().verify_token(value)
        if verified is None or verified.expires_at is None:
            return None
        subject = (verified.claims or {}).get("sub")
        if not isinstance(subject, str) or not subject:
            return None
        if self.routes_warehouse_accounts:
            if self._dsn_for_subject(subject) is None:
                return None
        elif subject != self._subject:
            return None
        # The HTTP/SSE transport binds a session to the verified principal.
        # Different subjects may have the same OAuth application client_id.
        verified.subject = subject
        return verified


def build_auth():
    token = os.environ.get("LAKE_MCP_AUTH_TOKEN")
    token_file = os.environ.get("LAKE_MCP_AUTH_TOKEN_FILE")
    jwks = os.environ.get("LAKE_MCP_AUTH_JWKS_URI")
    issuer = os.environ.get("LAKE_MCP_AUTH_ISSUER")
    audience = os.environ.get("LAKE_MCP_AUTH_AUDIENCE")
    subject = os.environ.get("LAKE_MCP_AUTH_SUBJECT")
    warehouse_map = os.environ.get("LAKE_MCP_WAREHOUSE_MAP_FILE")
    if any((jwks, issuer, audience, subject, warehouse_map)):
        if token is not None or token_file or not all((jwks, issuer, audience)) or bool(subject) == bool(warehouse_map):
            raise ValueError("Configure JWT issuer, audience, JWKS URI and exactly one subject or warehouse map")
        if urlsplit(jwks).scheme != "https" or not urlsplit(jwks).hostname:
            raise ValueError("LAKE_MCP_AUTH_JWKS_URI must be an HTTPS URL")
        return LakeJWTVerifier(
            jwks_uri=jwks,
            issuer=issuer,
            audience=audience,
            required_scopes=["lake"],
            subject=subject,
            warehouse_map=warehouse_map,
        )
    required = os.environ.get("LAKE_MCP_REQUIRE_AUTH", "false").lower()
    if required not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("Invalid LAKE_MCP_REQUIRE_AUTH; use true or false")
    if token is not None and (len(token.encode()) < 32 or token != token.strip()):
        raise ValueError("LAKE_MCP_AUTH_TOKEN must be at least 32 bytes without surrounding whitespace")
    if token_file:
        if token is not None:
            raise ValueError("Configure one bearer token source")
        return FileTokenVerifier(token_file)
    if required in {"true", "1", "yes", "on"} and not token:
        raise ValueError("LAKE_MCP_REQUIRE_AUTH requires LAKE_MCP_AUTH_TOKEN")
    if not token:
        return None
    return StaticTokenVerifier(tokens={token: {"client_id": "lake-mcp", "scopes": ["lake", "lake:write"]}}, required_scopes=["lake"])


def get_network_request():
    try:
        return get_http_request()
    except RuntimeError:
        return None


class NetworkTransportMiddleware:
    def __init__(self, app, *, anonymous):
        self.app = app
        self.anonymous = anonymous

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            peer = scope.get("client")
            loopback = peer is not None and _is_loopback(peer[0])
            if not loopback and (self.anonymous or scope["scheme"] != "https"):
                response = PlainTextResponse("Authenticated HTTPS required", status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


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
    options = {
        "host": host,
        "middleware": [
            Middleware(TrustedHostMiddleware, allowed_hosts=hosts),
            Middleware(NetworkTransportMiddleware, anonymous=auth is None),
        ],
    }
    if cert:
        options["uvicorn_config"] = {"ssl_certfile": cert, "ssl_keyfile": key}
    return options
