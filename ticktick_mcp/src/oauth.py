import base64
import binascii
import hashlib
import hmac
import html
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response


READ_SCOPE = "ticktick:read"
WRITE_SCOPE = "ticktick:write"
ALL_SCOPES = [READ_SCOPE, WRITE_SCOPE]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _append_query(url: str, **params: str | None) -> str:
    parsed = urlparse(url)
    query_params = [(k, v) for k, vs in parse_qs(parsed.query).items() for v in vs]
    for key, value in params.items():
        if value is not None:
            query_params.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(query_params)))


@dataclass
class PendingAuthorization:
    client_id: str
    state: str | None
    scopes: list[str]
    code_challenge: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    resource: str | None
    expires_at: float


class SingleUserOAuthProvider:
    """Minimal single-user OAuth 2.1 provider for ChatGPT MCP access."""

    def __init__(
        self,
        *,
        issuer_url: str,
        password: str,
        token_secret: str,
        access_token_ttl_seconds: int = 3600,
        refresh_token_ttl_seconds: int = 7_776_000,
        authorization_code_ttl_seconds: int = 300,
    ):
        if not password:
            raise ValueError("MCP_OAUTH_PASSWORD must be set when MCP_AUTH_MODE=oauth")
        if not token_secret:
            raise ValueError("MCP_OAUTH_TOKEN_SECRET must be set when MCP_AUTH_MODE=oauth")

        self.issuer_url = issuer_url.rstrip("/")
        self._password = password
        self._token_secret = token_secret.encode("utf-8")
        self._access_token_ttl_seconds = access_token_ttl_seconds
        self._refresh_token_ttl_seconds = refresh_token_ttl_seconds
        self._authorization_code_ttl_seconds = authorization_code_ttl_seconds
        self._pending: dict[str, PendingAuthorization] = {}
        self._authorization_codes: dict[str, AuthorizationCode] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if not client_id:
            return None

        payload = self._decode_signed("client", client_id)
        if not payload:
            return None

        token_endpoint_auth_method = payload.get("token_endpoint_auth_method") or "client_secret_post"
        client_secret = None
        if token_endpoint_auth_method != "none":
            client_secret = self._client_secret_for(client_id)

        return OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=payload.get("client_id_issued_at"),
            client_secret_expires_at=payload.get("client_secret_expires_at"),
            redirect_uris=payload.get("redirect_uris"),
            token_endpoint_auth_method=token_endpoint_auth_method,
            grant_types=payload.get("grant_types") or ["authorization_code", "refresh_token"],
            response_types=payload.get("response_types") or ["code"],
            scope=payload.get("scope"),
            client_name=payload.get("client_name"),
            client_uri=payload.get("client_uri"),
            logo_uri=payload.get("logo_uri"),
            contacts=payload.get("contacts"),
            tos_uri=payload.get("tos_uri"),
            policy_uri=payload.get("policy_uri"),
            jwks_uri=payload.get("jwks_uri"),
            jwks=payload.get("jwks"),
            software_id=payload.get("software_id"),
            software_version=payload.get("software_version"),
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        requested_scopes = set((client_info.scope or "").split())
        if requested_scopes and not requested_scopes.issubset(set(ALL_SCOPES)):
            invalid = ", ".join(sorted(requested_scopes - set(ALL_SCOPES)))
            raise RegistrationError("invalid_client_metadata", f"Unsupported scopes: {invalid}")
        if client_info.token_endpoint_auth_method not in {None, "none", "client_secret_post", "client_secret_basic"}:
            raise RegistrationError(
                "invalid_client_metadata",
                f"Unsupported token endpoint auth method: {client_info.token_endpoint_auth_method}",
            )

        if not client_info.scope:
            client_info.scope = " ".join(ALL_SCOPES)

        payload = {
            "redirect_uris": [str(uri) for uri in (client_info.redirect_uris or [])],
            "token_endpoint_auth_method": client_info.token_endpoint_auth_method or "client_secret_post",
            "grant_types": client_info.grant_types,
            "response_types": client_info.response_types,
            "scope": client_info.scope,
            "client_name": client_info.client_name,
            "client_uri": str(client_info.client_uri) if client_info.client_uri else None,
            "logo_uri": str(client_info.logo_uri) if client_info.logo_uri else None,
            "contacts": client_info.contacts,
            "tos_uri": str(client_info.tos_uri) if client_info.tos_uri else None,
            "policy_uri": str(client_info.policy_uri) if client_info.policy_uri else None,
            "jwks_uri": str(client_info.jwks_uri) if client_info.jwks_uri else None,
            "jwks": client_info.jwks,
            "software_id": client_info.software_id,
            "software_version": client_info.software_version,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": client_info.client_secret_expires_at,
        }

        client_id = self._encode_signed("client", payload)
        client_info.client_id = client_id
        client_info.client_id_issued_at = payload["client_id_issued_at"]
        if payload["token_endpoint_auth_method"] == "none":
            client_info.client_secret = None
            client_info.client_secret_expires_at = None
        else:
            client_info.client_secret = self._client_secret_for(client_id)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not client.client_id:
            raise AuthorizeError("invalid_request", "Missing client_id")

        scopes = params.scopes or ALL_SCOPES
        if not set(scopes).issubset(set(ALL_SCOPES)):
            raise AuthorizeError("invalid_scope", "Unsupported TickTick MCP scope")

        pending_id = secrets.token_urlsafe(32)
        self._pending[pending_id] = PendingAuthorization(
            client_id=client.client_id,
            state=params.state,
            scopes=scopes,
            code_challenge=params.code_challenge,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            expires_at=time.time() + 600,
        )
        return f"{self.issuer_url}/oauth/login?pending={pending_id}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        code = self._authorization_codes.get(authorization_code)
        if code and code.client_id == client.client_id:
            return code
        return None

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        self._authorization_codes.pop(authorization_code.code, None)
        return self._issue_oauth_token(
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        payload = self._decode_signed("refresh", refresh_token)
        if not payload or payload.get("client_id") != client.client_id:
            return None
        if payload.get("exp", 0) < int(time.time()):
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=payload["client_id"],
            scopes=payload.get("scopes") or [],
            expires_at=payload.get("exp"),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        requested = scopes or refresh_token.scopes
        if not set(requested).issubset(set(refresh_token.scopes)):
            raise TokenError("invalid_scope", "Cannot request scopes outside the refresh token")
        payload = self._decode_signed("refresh", refresh_token.token) or {}
        return self._issue_oauth_token(
            client_id=client.client_id or refresh_token.client_id,
            scopes=requested,
            resource=payload.get("resource"),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        payload = self._decode_signed("access", token)
        if not payload:
            return None
        if payload.get("exp", 0) < int(time.time()):
            return None
        return AccessToken(
            token=token,
            client_id=payload.get("client_id") or "chatgpt",
            scopes=payload.get("scopes") or [],
            expires_at=payload.get("exp"),
            resource=payload.get("resource"),
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self.load_access_token(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        return None

    async def handle_login(self, request: Request) -> Response:
        if request.method == "GET":
            return self._login_form(request.query_params.get("pending") or "")

        form = await request.form()
        return await self._complete_login(form)

    async def _complete_login(self, form: FormData) -> Response:
        pending_id = str(form.get("pending") or "")
        password = str(form.get("password") or "")
        pending = self._pending.get(pending_id)
        if not pending:
            return HTMLResponse("OAuth request expired or does not exist.", status_code=400)
        if pending.expires_at < time.time():
            self._pending.pop(pending_id, None)
            return HTMLResponse("OAuth request expired. Please reconnect from ChatGPT.", status_code=400)
        if not hmac.compare_digest(password.encode("utf-8"), self._password.encode("utf-8")):
            return self._login_form(pending_id, error="Incorrect password.", status_code=401)

        self._pending.pop(pending_id, None)
        code_value = secrets.token_urlsafe(32)
        self._authorization_codes[code_value] = AuthorizationCode(
            code=code_value,
            scopes=pending.scopes,
            expires_at=time.time() + self._authorization_code_ttl_seconds,
            client_id=pending.client_id,
            code_challenge=pending.code_challenge,
            redirect_uri=pending.redirect_uri,
            redirect_uri_provided_explicitly=pending.redirect_uri_provided_explicitly,
            resource=pending.resource,
        )
        redirect_url = _append_query(pending.redirect_uri, code=code_value, state=pending.state)
        return RedirectResponse(redirect_url, status_code=302, headers={"Cache-Control": "no-store"})

    def _login_form(self, pending_id: str, error: str | None = None, status_code: int = 200) -> HTMLResponse:
        safe_pending = html.escape(pending_id, quote=True)
        error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
        body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize TickTick MCP</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f7f7f5; color: #202124; }}
    main {{ max-width: 420px; margin: 12vh auto; padding: 32px; background: white; border: 1px solid #deded8; border-radius: 8px; }}
    h1 {{ font-size: 22px; margin: 0 0 12px; }}
    p {{ color: #5f6368; line-height: 1.45; }}
    label {{ display: block; font-weight: 600; margin: 24px 0 8px; }}
    input {{ box-sizing: border-box; width: 100%; padding: 12px; border: 1px solid #c9c9c3; border-radius: 6px; font-size: 16px; }}
    button {{ width: 100%; margin-top: 18px; padding: 12px; border: 0; border-radius: 6px; background: #1f6feb; color: white; font-weight: 700; font-size: 16px; }}
    .error {{ color: #b3261e; }}
  </style>
</head>
<body>
  <main>
    <h1>Authorize TickTick MCP</h1>
    <p>Enter your private MCP password to let ChatGPT access your TickTick tools.</p>
    {error_html}
    <form method="post" action="/oauth/login">
      <input type="hidden" name="pending" value="{safe_pending}">
      <label for="password">MCP password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Authorize</button>
    </form>
  </main>
</body>
</html>"""
        return HTMLResponse(body, status_code=status_code)

    def _issue_oauth_token(self, *, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        now = int(time.time())
        access_payload = {
            "client_id": client_id,
            "scopes": scopes,
            "resource": resource,
            "iat": now,
            "exp": now + self._access_token_ttl_seconds,
            "jti": secrets.token_urlsafe(16),
        }
        refresh_payload = {
            "client_id": client_id,
            "scopes": scopes,
            "resource": resource,
            "iat": now,
            "exp": now + self._refresh_token_ttl_seconds,
            "jti": secrets.token_urlsafe(16),
        }
        return OAuthToken(
            access_token=self._encode_signed("access", access_payload),
            token_type="Bearer",
            expires_in=self._access_token_ttl_seconds,
            scope=" ".join(scopes),
            refresh_token=self._encode_signed("refresh", refresh_payload),
        )

    def _client_secret_for(self, client_id: str) -> str:
        digest = hmac.new(self._token_secret, client_id.encode("utf-8"), hashlib.sha256).digest()
        return _b64url_encode(digest)

    def _encode_signed(self, token_type: str, payload: dict[str, Any]) -> str:
        clean_payload = {key: value for key, value in payload.items() if value is not None}
        payload_bytes = json.dumps(clean_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)
        signing_input = f"{token_type}.{payload_b64}".encode("ascii")
        signature = hmac.new(self._token_secret, signing_input, hashlib.sha256).digest()
        return f"{token_type}.{payload_b64}.{_b64url_encode(signature)}"

    def _decode_signed(self, token_type: str, token: str) -> dict[str, Any] | None:
        try:
            prefix, payload_b64, signature_b64 = token.split(".", 2)
            if prefix != token_type:
                return None
            signing_input = f"{prefix}.{payload_b64}".encode("ascii")
            expected = hmac.new(self._token_secret, signing_input, hashlib.sha256).digest()
            supplied = _b64url_decode(signature_b64)
            if not hmac.compare_digest(expected, supplied):
                return None
            payload = json.loads(_b64url_decode(payload_b64))
            if not isinstance(payload, dict):
                return None
            return payload
        except (binascii.Error, UnicodeDecodeError, ValueError, json.JSONDecodeError, TypeError):
            return None
