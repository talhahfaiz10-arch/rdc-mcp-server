# Render Termux MCP Gateway

A small Python MCP server intended for deployment as a Render web service.
It exposes an MCP Streamable HTTP endpoint at `/mcp`, a public health endpoint
at `/health`, and named Termux bridge tools protected by bearer authentication.

## Important deployment boundary

This gateway does **not** automatically make a phone's localhost reachable from
Render. The Termux bridge must have a secure network route from Render (for
example, a properly authenticated tunnel or relay). Do not expose the phone's
bridge directly to the public internet without authentication and transport
security.

The gateway intentionally does not offer arbitrary shell execution. The
`termux_system_status` tool expects the bridge to implement a named,
read-only `POST /approved-operation` operation. If your existing bridge only
supports `/health` and a generic `/shell` action, do not connect it to this
gateway until the bridge has a narrow allowlist and validates requests itself.

## Files

- `app/server.py`: MCP Streamable HTTP server and bearer-token middleware.
- `requirements.txt`: Python dependencies.
- `render.yaml`: Render Blueprint for a free Singapore-region web service.
- `.env.example`: environment variable template (no real credentials).

## Run locally

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
export MCP_BEARER_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m app.server
```

On Windows PowerShell, set the variable with:
```powershell
$env:MCP_BEARER_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(48))"
python -m app.server
```

Check `http://127.0.0.1:10000/health`. MCP clients should connect to
`http://127.0.0.1:10000/mcp` and send `Authorization: Bearer <token>`.

## Deploy to Render (do not deploy until approved)

1. Create a **new, private GitHub repository** and push these project files.
2. Confirm the correct Render workspace with the account owner.
3. In Render, choose **New + → Web Service**, select the repository, and use:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `python -m app.server`
   - Plan: Free
   - Region: Singapore (or closest supported region to the bridge)
   - Health check path: `/health`
4. Add these environment variables in Render's dashboard:
   - `MCP_BEARER_TOKEN`: generate a unique, long random secret.
   - `TERMUX_BRIDGE_URL`: only after a secure route to the bridge exists.
   - `TERMUX_BRIDGE_TOKEN`: a separate secret for authenticating to the bridge.
   - `BRIDGE_TIMEOUT_SECONDS`: `8`
5. Deploy and verify `/health` returns `{"status":"ok",...}`.
6. Verify `/mcp` rejects missing/incorrect bearer tokens before configuring a client.
7. Configure your MCP client with the HTTPS URL ending in `/mcp` and the bearer token.

`render.yaml` is an optional Blueprint. Review its region, service name, plan, and
secret prompts before using it. The service is **not deployed by this project
generation**.

## Security checklist

- Never commit `.env`, tokens, or credentials.
- Use a distinct gateway token and bridge token.
- Keep the phone bridge behind authenticated HTTPS or a private tunnel.
- Enforce an operation allowlist on both gateway and phone bridge.
- Do not pass user-supplied command strings to a shell.
- Rotate any token that has been exposed.
- Free services may sleep when idle; allow for cold starts.
- MCP client authentication configuration varies by client; confirm it supports
  custom bearer headers for remote Streamable HTTP.
