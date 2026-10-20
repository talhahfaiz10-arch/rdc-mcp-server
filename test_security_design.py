"""Lightweight static checks for the intended security posture."""
from pathlib import Path

def test_server_has_bearer_auth_and_no_shell_tool():
    source = Path("app/server.py").read_text()
    assert 'WWW-Authenticate' in source
    assert 'arbitrary_shell_execution' in source
    assert 'async def termux_bridge_health' in source
    assert 'async def termux_system_status' in source
    assert 'create_subprocess_shell' not in source
    assert 'os.system(' not in source
