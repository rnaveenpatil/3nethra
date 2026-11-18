import hashlib
import shutil

import pytest

from agent.terminal import ReadonlyTerminal, TerminalError


def test_terminal_rejects_shell_and_outside_paths(tmp_path):
    terminal = ReadonlyTerminal(tmp_path)
    with pytest.raises(TerminalError):
        terminal.validate(["sh", "-c", "id"])
    with pytest.raises(TerminalError):
        terminal.validate(["file", "/etc/passwd"])
    with pytest.raises(TerminalError):
        terminal.validate(["file", "../escape"])


@pytest.mark.asyncio
async def test_terminal_hashes_workspace_file(tmp_path):
    if shutil.which("sha256sum") is None:
        pytest.skip("sha256sum is unavailable")
    target = tmp_path / "sample.txt"
    target.write_bytes(b"hello")
    terminal = ReadonlyTerminal(tmp_path)
    result = await terminal.run(["sha256sum", "sample.txt"])
    assert result.returncode == 0
    assert hashlib.sha256(b"hello").hexdigest() in result.stdout
