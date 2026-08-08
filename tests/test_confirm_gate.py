"""Tests for the CLI confirm gate in _dispatch.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from beachhead.cli._dispatch import _cli_confirm


@pytest.mark.asyncio
async def test_confirm_accepts_y():
    with patch.object(
        __builtins__["__import__"].__self__,  # type: ignore[union-attr]
        "__import__",
        side_effect=ImportError,
    ):
        pass
    # Simpler approach: patch console.input
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", return_value="y"):
        assert await _cli_confirm("Do this?") is True


@pytest.mark.asyncio
async def test_confirm_accepts_yes():
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", return_value="yes"):
        assert await _cli_confirm("Do this?") is True


@pytest.mark.asyncio
async def test_confirm_rejects_n():
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", return_value="n"):
        assert await _cli_confirm("Do this?") is False


@pytest.mark.asyncio
async def test_confirm_rejects_empty():
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", return_value=""):
        assert await _cli_confirm("Do this?") is False


@pytest.mark.asyncio
async def test_confirm_handles_eof():
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", side_effect=EOFError):
        assert await _cli_confirm("Do this?") is False


@pytest.mark.asyncio
async def test_confirm_handles_keyboard_interrupt():
    from beachhead.cli._dispatch import console

    with patch.object(console, "input", side_effect=KeyboardInterrupt):
        assert await _cli_confirm("Do this?") is False
