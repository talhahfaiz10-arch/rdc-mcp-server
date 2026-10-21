"""Protocol-level regression tests for the custom OAuth endpoints."""
import base64
import hashlib
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.testclient import TestClient

from app import oauth_support
from app.server import app


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def setup_function():
    oauth_support.MASTER_SECRET = "test-only-secret-that-is-not-used-in-production"
    oauth_support._codes.clear()


def test_metadata_advertises_issuer_response_support():
    with TestClient(app) as client:
        metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == oauth_support.BASE_URL
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert "S256" in metadata["code_challenge_methods_supported"]


def test_registration_and_authorization_response_include_issuer():
    redirect_uri = "http://127.0.0.1:8787/callback"
    verifier = "a" * 43
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    client = TestClient(app, follow_redirects=False)
    reg = client.post("/register", json={"client_name": "Regression test", "redirect_uris": [redirect_uri]})
    assert reg.status_code == 201, reg.text
    cid = reg.json()["client_id"]
    params = {
        "response_type": "code", "client_id": cid, "redirect_uri": redirect_uri,
        "state": "test-state", "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": oauth_support.RESOURCE,
        "scope": "mcp:tools",
    }
    page = client.get("/authorize", params=params)
    assert page.status_code == 200
    params.update({"username": "termux", "password": oauth_support.MASTER_SECRET})
    response = client.post("/authorize", data=params)
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["test-state"]
    assert query["iss"] == [oauth_support.BASE_URL]
    assert "code" in query


def test_wrong_pkce_verifier_does_not_consume_authorization_code():
    redirect_uri = "http://127.0.0.1:8787/callback"
    verifier = "b" * 43
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    client = TestClient(app, follow_redirects=False)
    reg = client.post("/register", json={"client_name": "PKCE test", "redirect_uris": [redirect_uri]})
    cid = reg.json()["client_id"]
    params = {"response_type": "code", "client_id": cid, "redirect_uri": redirect_uri,
              "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
              "resource": oauth_support.RESOURCE, "scope": "mcp:tools"}
    client.get("/authorize", params=params)
    params.update({"username": "termux", "password": oauth_support.MASTER_SECRET})
    query = parse_qs(urlparse(client.post("/authorize", data=params).headers["location"]).query)
    code = query["code"][0]
    bad = client.post("/token", data={"grant_type": "authorization_code", "code": code,
        "client_id": cid, "redirect_uri": redirect_uri, "resource": oauth_support.RESOURCE,
        "code_verifier": "c" * 43})
    assert bad.status_code == 400
    good = client.post("/token", data={"grant_type": "authorization_code", "code": code,
        "client_id": cid, "redirect_uri": redirect_uri, "resource": oauth_support.RESOURCE,
        "code_verifier": verifier})
    assert good.status_code == 200, good.text
    token = good.json()["access_token"]
    assert oauth_support.valid_token(token)
    replay = client.post("/token", data={"grant_type": "authorization_code", "code": code,
        "client_id": cid, "redirect_uri": redirect_uri, "resource": oauth_support.RESOURCE,
        "code_verifier": verifier})
    assert replay.status_code == 400


def test_authorize_rejects_wrong_resource_with_issuer_bound_error():
    redirect_uri = "http://127.0.0.1:8787/callback"
    client = TestClient(app, follow_redirects=False)
    reg = client.post("/register", json={"client_name": "Resource test", "redirect_uris": [redirect_uri]})
    params = {"response_type": "code", "client_id": reg.json()["client_id"],
              "redirect_uri": redirect_uri, "state": "s", "code_challenge": "A" * 43,
              "code_challenge_method": "S256", "resource": "https://wrong.example/mcp"}
    response = client.get("/authorize", params=params)
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_target"]
    assert query["iss"] == [oauth_support.BASE_URL]
    assert query["state"] == ["s"]


def test_mcp_tool_call_returns_oauth_metadata_challenge():
    client = TestClient(app, follow_redirects=False)
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 41, "method": "tools/call",
        "params": {"name": "termux_system_status", "arguments": {}}})
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"] is True
    challenges = result["_meta"]["mcp/www_authenticate"]
    assert len(challenges) == 1
    assert "resource_metadata=" in challenges[0]
    assert 'error="invalid_token"' in challenges[0]


def test_mcp_tool_list_declares_per_tool_security_schemes():
    import asyncio
    from app.server import _list_tools_with_security_schemes

    tools = asyncio.run(_list_tools_with_security_schemes())
    by_name = {tool.name: tool.model_dump(by_alias=True) for tool in tools}
    assert by_name["termux_system_status"]["securitySchemes"] == [{"type": "oauth2", "scopes": ["mcp:tools"]}]
    assert by_name["termux_bridge_health"]["securitySchemes"] == [{"type": "oauth2", "scopes": ["mcp:tools"]}]
    assert by_name["termux_approved_operations"]["securitySchemes"] == [{"type": "noauth"}]


def test_master_secret_is_not_accepted_as_a_bearer_access_token():
    client = TestClient(app, follow_redirects=False)
    response = client.get("/mcp", headers={"Authorization": f"Bearer {oauth_support.MASTER_SECRET}"})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
