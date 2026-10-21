# OAuth 2.1 helper for the Render-hosted MCP gateway.
# Uses the existing MCP_BEARER_TOKEN as the local authorization-page secret and
# HMAC signing key; never sends that secret back to the OAuth client.
import asyncio, base64, hashlib, hmac, json, os, secrets, time
from urllib.parse import parse_qs, urlencode, urlparse
from typing import Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://rdc-mcp-server.onrender.com").rstrip("/")
RESOURCE = BASE_URL + "/mcp"
MASTER_SECRET = os.getenv("MCP_BEARER_TOKEN", "")
_clients: dict[str, dict[str, Any]] = {}
_codes: dict[str, dict[str, Any]] = {}
TTL = 3600

def enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def issue(payload: dict[str, Any]) -> str:
    body = enc(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = enc(hmac.new(MASTER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return body + "." + sig

def valid_token(token: str) -> bool:
    try:
        body, sig = token.split(".", 1)
        expected = enc(hmac.new(MASTER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not MASTER_SECRET or not hmac.compare_digest(sig, expected): return False
        p = json.loads(dec(body))
        return p.get("iss") == BASE_URL and p.get("aud") == RESOURCE and p.get("scope") == "mcp:tools" and int(p.get("exp", 0)) > int(time.time())
    except Exception:
        return False

def valid_redirect(uri: str) -> bool:
    try:
        p = urlparse(uri)
        return bool(p.hostname and (p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1", "::1"))))
    except Exception: return False

class OAuthBearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"
        public = {"/", "/health", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/register", "/authorize", "/token"}
        if path in public or path in ("/relay/agent/next", "/relay/agent/result"):
            return await call_next(request)
        h = request.headers.get("authorization", "")
        token = h[7:].strip() if h.lower().startswith("bearer ") else ""
        # Keep existing private token available for manual recovery, too.
        legacy = bool(MASTER_SECRET) and hmac.compare_digest(token, MASTER_SECRET)
        if not (legacy or valid_token(token)):
            return JSONResponse({"error":"unauthorized"}, status_code=401, headers={"WWW-Authenticate": f'Bearer resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'})
        return await call_next(request)

async def protected_resource(request: Request):
    return JSONResponse({"resource":RESOURCE,"authorization_servers":[BASE_URL],"scopes_supported":["mcp:tools"],"bearer_methods_supported":["header"]})

async def auth_metadata(request: Request):
    return JSONResponse({"issuer":BASE_URL,"authorization_endpoint":BASE_URL+"/authorize","token_endpoint":BASE_URL+"/token","registration_endpoint":BASE_URL+"/register","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":["mcp:tools"]})

async def register(request: Request):
    try: b = await request.json()
    except Exception: return JSONResponse({"error":"invalid_client_metadata"}, status_code=400)
    uris = b.get("redirect_uris")
    if not isinstance(uris,list) or not uris or not all(isinstance(u,str) and valid_redirect(u) for u in uris):
        return JSONResponse({"error":"invalid_redirect_uri"}, status_code=400)
    cid = secrets.token_urlsafe(24)
    _clients[cid] = {"name":str(b.get("client_name","MCP client"))[:100],"uris":uris}
    return JSONResponse({"client_id":cid,"client_name":_clients[cid]["name"],"redirect_uris":uris,"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"},status_code=201)

def safe(s: str) -> str:
    return s.replace("&","&amp;").replace('"',"&quot;").replace("<","&lt;").replace(">","&gt;")

async def authorize(request: Request):
    if request.method == "GET":
        v = dict(request.query_params)
    else:
        v = {k: vals[0] for k, vals in parse_qs((await request.body()).decode(),keep_blank_values=True).items()}
    cid, uri = str(v.get("client_id","")), str(v.get("redirect_uri",""))
    c = _clients.get(cid)
    if not c or uri not in c["uris"]: return HTMLResponse("<h2>Invalid client or redirect URI</h2>",status_code=400)
    if request.method == "GET":
        hidden = "".join(f'<input type="hidden" name="{k}" value="{safe(str(v.get(k,"")))}">' for k in ("client_id","redirect_uri","state","code_challenge","code_challenge_method","resource","scope","response_type"))
        return HTMLResponse(f"""<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Termux Recovery</title><main style="font:16px system-ui;max-width:440px;margin:40px auto;padding:20px"><h2>Authorize Termux Recovery</h2><p>{safe(c['name'])} requests read-only Termux status tools.</p><form method="post" action="/authorize">{hidden}<label>Username</label><input name="username" value="termux" required style="display:block;width:100%;padding:12px;margin:8px 0"><label>Termux MCP secret</label><input type="password" name="password" required style="display:block;width:100%;padding:12px;margin:8px 0"><button style="padding:12px">Authorize read-only tools</button></form><p>Arbitrary shell execution is disabled.</p></main>""")
    if not MASTER_SECRET or v.get("username") != "termux" or not hmac.compare_digest(str(v.get("password","")),MASTER_SECRET):
        return HTMLResponse("<h2>Login failed</h2><p>Return to the connection setup and try again.</p>",status_code=401)
    if v.get("code_challenge_method") != "S256" or not v.get("code_challenge") or v.get("resource",RESOURCE) != RESOURCE:
        return JSONResponse({"error":"invalid_request"},status_code=400)
    code = secrets.token_urlsafe(32)
    _codes[code] = {"cid":cid,"uri":uri,"challenge":v["code_challenge"],"state":v.get("state",""),"exp":time.time()+300}
    q={"code":code}
    if v.get("state"): q["state"]=v["state"]
    return RedirectResponse(uri+("&" if "?" in uri else "?")+urlencode(q),status_code=302)

async def token(request: Request):
    v = {k: vals[0] for k, vals in parse_qs((await request.body()).decode(),keep_blank_values=True).items()}
    if v.get("grant_type") != "authorization_code": return JSONResponse({"error":"unsupported_grant_type"},status_code=400)
    c = _codes.pop(v.get("code",""),None)
    if not c or c["exp"] < time.time() or v.get("client_id") != c["cid"] or v.get("redirect_uri") != c["uri"] or v.get("resource",RESOURCE) != RESOURCE:
        return JSONResponse({"error":"invalid_grant"},status_code=400)
    verifier = v.get("code_verifier","")
    if not verifier or enc(hashlib.sha256(verifier.encode()).digest()) != c["challenge"]:
        return JSONResponse({"error":"invalid_grant"},status_code=400)
    now=int(time.time())
    access=issue({"iss":BASE_URL,"aud":RESOURCE,"sub":c["cid"],"scope":"mcp:tools","iat":now,"exp":now+TTL})
    return JSONResponse({"access_token":access,"token_type":"Bearer","expires_in":TTL,"scope":"mcp:tools"},headers={"Cache-Control":"no-store","Pragma":"no-cache"})

def install_oauth(app):
    app.add_route("/.well-known/oauth-protected-resource", protected_resource, methods=["GET"])
    app.add_route("/.well-known/oauth-authorization-server", auth_metadata, methods=["GET"])
    app.add_route("/register", register, methods=["POST"])
    app.add_route("/authorize", authorize, methods=["GET","POST"])
    app.add_route("/token", token, methods=["POST"])
    app.add_middleware(OAuthBearerAuthMiddleware)
