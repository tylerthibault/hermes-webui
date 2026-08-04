"""Security regression tests for session-scoped chat attachments."""

import os
import stat

import pytest

from api.upload import _write_private_attachment


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not enforced on Windows")


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_private_attachment_uses_owner_only_directory_and_file_modes(monkeypatch, tmp_path):
    inbox = tmp_path / "attachment-inbox"
    monkeypatch.setenv("HERMES_WEBUI_ATTACHMENT_DIR", str(inbox))

    previous_umask = os.umask(0)
    try:
        dest = _write_private_attachment("session-123", "family-budget.pdf", b"private")
    finally:
        os.umask(previous_umask)

    assert dest.read_bytes() == b"private"
    assert _mode(inbox) == 0o700
    assert _mode(dest.parent) == 0o700
    assert _mode(dest) == 0o600


def test_private_attachment_create_is_exclusive_and_deduplicates(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_WEBUI_ATTACHMENT_DIR", str(tmp_path / "inbox"))

    first = _write_private_attachment("session-123", "notes.txt", b"first")
    second = _write_private_attachment("session-123", "notes.txt", b"second")

    assert first.name == "notes.txt"
    assert second.name == "notes-1.txt"
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"
