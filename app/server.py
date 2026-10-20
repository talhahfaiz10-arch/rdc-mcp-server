import asyncio
import hmac
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

SERVICE_NAME = "render-termux-mcp"
MCP_BEARER_TOKEN = os.getenv("MCP_BEARER_TOKEN", "")
TERMUX_BRIDGE_URL = os.getenv("TERMUX_BRIDGE_URL", "").rstrip("/")
TERMUX_BRIDGE_TOKEN = os.getenv("TERMUX_BRIDGE_TOKEN", "")
BRIDGE_TIMEOUT_SECONDS = float(os.getenv("BRIDGE_TIMEOUT_SECONDS", "8"))

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
    result = await _bridge_request("/health")
    return {
        "service": SERVICE_NAME,
        "bridge_configured": bool(TERMUX_BRIDGE_URL),
        **result,
    }


@mcp.tool()
async def termux_system_status() -> dict[str, Any]:
    """Request the named, read-only system_status operation from the bridge.

    The bridge must implement POST /approved-operation with {"operation":"system_status"}.
    This is a named operation, not a free-form shell command.
    """
    if "system_status" not in APPROVED_OPERATIONS:
        return {"ok": False, "error": "operation_not_approved"}
    return await _bridge_request(
        "/approved-operation", {"operation": "system_status"}
    )


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
app = mcp.streamable_http_app()
app.add_middleware(BearerAuthMiddleware)


async def health(request: Request):
    return JSONResponse({"status": "ok", "service": SERVICE_NAME, "mcp_path": "/mcp"})


async def root(request: Request):
    return PlainTextResponse(
        f"{SERVICE_NAME} is running. MCP endpoint: /mcp; health endpoint: /health"
    )


app.add_route("/health", health, methods=["GET"])
app.add_route("/", root, methods=["GET"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
