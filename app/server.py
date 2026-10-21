import asyncio
import hmac
import os
import time
import uuid
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

SERVICE_NAME = "render-termux-mcp"
MCP_BEARER_TOKEN = os.getenv("MCP_BEARER_TOKEN", "")
TERMUX_BRIDGE_URL = os.getenv("TERMUX_BRIDGE_URL", "").rstrip("/")
TERMUX_BRIDGE_TOKEN = os.getenv("TERMUX_BRIDGE_TOKEN", "")
BRIDGE_TIMEOUT_SECONDS = float(os.getenv("BRIDGE_TIMEOUT_SECONDS", "8"))
RELAY_WAIT_SECONDS = float(os.getenv("RELAY_WAIT_SECONDS", "25"))
# In-memory queue is appropriate for this single-instance starter relay. Jobs are
# deliberately limited to named, read-only operations; never accept shell text.
_relay_jobs: asyncio.Queue = asyncio.Queue()
_relay_pending: dict[str, asyncio.Future] = {}

# Keep this list narrow. These are named operations, not arbitrary shell input.
APPROVED_OPERATIONS = {
    "health": {"description": "Check whether the Termux bridge is reachable."},
    "system_status": {"description": "Read basic system status from the bridge, if implemented."},
}

mcp = FastMCP(SERVICE_NAME, stateless_http=True, json_response=True)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Render health checks can access this endpoint without credentials.
        if request.url.path.rstrip("/") == "/health":
            return await call_next(request)

        # Agent routes authenticate independently with TERMUX_BRIDGE_TOKEN.
        if request.url.path in ("/relay/agent/next", "/relay/agent/result"):
            return await call_next(request)

        # Protect the MCP endpoint and every other application route by default.
        supplied = request.headers.get("authorization", "")
        expected = f"Bearer {MCP_BEARER_TOKEN}" if MCP_BEARER_TOKEN else ""
        if not expected or not hmac.compare_digest(supplied, expected):
            return JSONResponse(
                {"error": "unauthorized", "message": "A valid bearer token is required."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


async def _bridge_request(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if not TERMUX_BRIDGE_URL:
        return {
            "ok": False,
            "error": "termux_bridge_not_configured",
            "message": "Set TERMUX_BRIDGE_URL to a reachable, authenticated bridge endpoint.",
        }

    headers = {}
    if TERMUX_BRIDGE_TOKEN:
        headers["Authorization"] = f"Bearer {TERMUX_BRIDGE_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=BRIDGE_TIMEOUT_SECONDS) as client:
            if payload is None:
                response = await client.get(f"{TERMUX_BRIDGE_URL}{path}", headers=headers)
            else:
                response = await client.post(
                    f"{TERMUX_BRIDGE_URL}{path}", headers=headers, json=payload
                )
            response.raise_for_status()
            try:
                data = response.json()
            except ValueError:
                data = {"response_text": response.text[:2000]}
            return {"ok": True, "status_code": response.status_code, "data": data}
    except httpx.TimeoutException:
        return {"ok": False, "error": "bridge_timeout", "message": "The bridge request timed out."}
    except httpx.HTTPStatusError as exc:
        return {
            "ok": False,
            "error": "bridge_http_error",
            "status_code": exc.response.status_code,
            "message": "The bridge rejected or failed the request.",
        }
    except httpx.HTTPError:
        return {
            "ok": False,
            "error": "bridge_unreachable",
            "message": "The bridge could not be reached. Check its URL, network route, and logs.",
        }


@mcp.tool()
async def termux_bridge_health() -> dict[str, Any]:
    """Check the configured Termux bridge's health. Does not execute shell commands."""
    if TERMUX_BRIDGE_URL:
        result = await _bridge_request("/health")
        return {"service": SERVICE_NAME, "bridge_configured": True, "route": "direct", **result}
    return {"service": SERVICE_NAME, "bridge_configured": bool(TERMUX_BRIDGE_TOKEN),
            "route": "render_polling_relay", "message": "Termux agent must be online to process requests."}


@mcp.tool()
async def termux_system_status() -> dict[str, Any]:
    """Request the named, read-only system_status operation from the bridge.

    The bridge must implement POST /approved-operation with {"operation":"system_status"}.
    This is a named operation, not a free-form shell command.
    """
    if "system_status" not in APPROVED_OPERATIONS:
        return {"ok": False, "error": "operation_not_approved"}
    if TERMUX_BRIDGE_URL:
        return await _bridge_request("/approved-operation", {"operation": "system_status"})
    if not TERMUX_BRIDGE_TOKEN:
        return {"ok": False, "error": "relay_not_configured", "message": "Set TERMUX_BRIDGE_TOKEN in Render."}
    job_id = uuid.uuid4().hex
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    _relay_pending[job_id] = future
    await _relay_jobs.put({"job_id": job_id, "operation": "system_status"})
    try:
        result = await asyncio.wait_for(future, timeout=RELAY_WAIT_SECONDS)
        return {"ok": True, "route": "render_polling_relay", "result": result}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "termux_agent_timeout", "message": "No Termux agent answered in time. Check the agent process and network."}
    finally:
        _relay_pending.pop(job_id, None)


@mcp.tool()
async def termux_approved_operations() -> dict[str, Any]:
    """List the named operations exposed by this gateway. No command is executed."""
    return {
        "operations": [
            {"name": name, **details} for name, details in APPROVED_OPERATIONS.items()
        ],
        "arbitrary_shell_execution": False,
    }


# Streamable HTTP endpoint is provided by the MCP SDK at /mcp.
# Render terminates public HTTPS and forwards the service Host header; explicitly
# allow only this service's public hostname rather than the SDK localhost default.
transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["rdc-mcp-server.onrender.com", "rdc-mcp-server.onrender.com:*"],
    allowed_origins=["https://rdc-mcp-server.onrender.com"],
)
app = mcp.streamable_http_app(transport_security=transport_security)
app.add_middleware(BearerAuthMiddleware)




async def _agent_authorized(request: Request) -> bool:
    supplied = request.headers.get("authorization", "")
    expected = f"Bearer {TERMUX_BRIDGE_TOKEN}" if TERMUX_BRIDGE_TOKEN else ""
    return bool(expected) and hmac.compare_digest(supplied, expected)


async def relay_next(request: Request):
    if not await _agent_authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # Short-poll keeps the agent simple and works over outbound HTTPS only.
    try:
        job = await asyncio.wait_for(_relay_jobs.get(), timeout=18)
        return JSONResponse({"job": job})
    except asyncio.TimeoutError:
        return JSONResponse({"job": None})


async def relay_result(request: Request):
    if not await _agent_authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)
    job_id = body.get("job_id")
    result = body.get("result")
    if not isinstance(job_id, str) or not isinstance(result, dict):
        return JSONResponse({"error": "job_id_and_result_required"}, status_code=400)
    future = _relay_pending.get(job_id)
    if future is None or future.done():
        return JSONResponse({"accepted": False, "reason": "job_not_pending"}, status_code=404)
    future.set_result(result)
    return JSONResponse({"accepted": True})


async def health(request: Request):
    return JSONResponse({"status": "ok", "service": SERVICE_NAME, "mcp_path": "/mcp"})


async def root(request: Request):
    return PlainTextResponse(
        f"{SERVICE_NAME} is running. MCP endpoint: /mcp; health endpoint: /health"
    )


app.add_route("/health", health, methods=["GET"])
app.add_route("/", root, methods=["GET"])
app.add_route("/relay/agent/next", relay_next, methods=["GET"])
app.add_route("/relay/agent/result", relay_result, methods=["POST"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
