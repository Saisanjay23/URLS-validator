"""
Unit tests for the Email Verification engine (SMTP/DNS probe).
"""

import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.email_checker import (
    check_email,
    resolve_mx_records,
    _read_smtp_response,
)
from backend.fast_checker import process_urls_stream


@pytest.mark.asyncio
async def test_check_email_invalid_format():
    result = await check_email("not-an-email")
    assert result["status"] == "uncertain"
    assert "Invalid email format" in result["reason"]
    assert result["confidence"] == 0
    assert result["http_code"] is None


@pytest.mark.asyncio
async def test_check_email_nonexistent_domain():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx:
        mock_mx.return_value = []
        result = await check_email("user@nonexistent-fake-domain-99999.xyz")
        assert result["status"] == "taken_down"
        assert result["confidence"] == 95
        assert "no mail servers" in result["reason"].lower()


@pytest.mark.asyncio
async def test_check_email_mocked_active():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("backend.email_checker.probe_smtp_mailbox", new_callable=AsyncMock) as mock_probe:
        mock_mx.return_value = ["mx.google.com"]
        mock_probe.return_value = (250, "2.1.5 OK recipient found")

        result = await check_email("activeuser@gmail.com")
        assert result["status"] == "active"
        assert result["platform"] == "gmail"
        assert result["http_code"] == 250
        assert result["confidence"] == 90
        assert "Mailbox exists" in result["reason"]


@pytest.mark.asyncio
async def test_check_email_mocked_taken_down():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("backend.email_checker.probe_smtp_mailbox", new_callable=AsyncMock) as mock_probe:
        mock_mx.return_value = ["mx.google.com"]
        mock_probe.return_value = (550, "5.1.1 The email account that you tried to reach does not exist")

        result = await check_email("deleteduser@gmail.com")
        assert result["status"] == "taken_down"
        assert result["platform"] == "gmail"
        assert result["http_code"] == 550
        assert result["confidence"] == 95
        assert "Mailbox does not exist" in result["reason"]


@pytest.mark.asyncio
async def test_check_email_mocked_timeout_network_block():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("backend.email_checker.probe_smtp_mailbox", new_callable=AsyncMock) as mock_probe:
        mock_mx.return_value = ["mx.google.com"]
        mock_probe.side_effect = asyncio.TimeoutError("Timeout")

        result = await check_email("user@gmail.com")
        assert result["status"] == "uncertain"
        assert result["platform"] == "gmail"
        assert "timed out" in result["reason"].lower() or "port 25" in result["reason"].lower()


@pytest.mark.asyncio
async def test_check_email_mocked_greylisted():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("backend.email_checker.probe_smtp_mailbox", new_callable=AsyncMock) as mock_probe:
        mock_mx.return_value = ["mx.custom.com"]
        mock_probe.return_value = (451, "4.3.0 Mailbox busy or greylisted")

        result = await check_email("info@custom.com")
        assert result["status"] == "uncertain"
        assert result["http_code"] == 451
        assert "deferred" in result["reason"].lower() or "greylist" in result["reason"].lower()


@pytest.mark.asyncio
async def test_read_smtp_response_multiline():
    reader = AsyncMock()
    # RFC 5321 multiline format: code-line... followed by code<space>line
    reader.readline.side_effect = [
        b"550-5.1.1 User does not exist\r\n",
        b"550-5.1.1 Check recipient address\r\n",
        b"550 5.1.1 Help at https://support.example.com\r\n",
    ]
    code, msg = await _read_smtp_response(reader)
    assert code == 550
    assert "User does not exist" in msg
    assert "Help at https://support.example.com" in msg


@pytest.mark.asyncio
async def test_process_urls_stream_email_integration():
    with patch("backend.email_checker.resolve_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("backend.email_checker.probe_smtp_mailbox", new_callable=AsyncMock) as mock_probe:
        mock_mx.return_value = ["mx.google.com"]
        mock_probe.side_effect = [
            (250, "OK"),
            (550, "5.1.1 User unknown"),
        ]

        items = ["live@gmail.com", "dead@gmail.com"]
        events = []
        summary = None
        async for evt in process_urls_stream(items):
            if evt.get("type") == "result":
                events.append(evt)
            if evt.get("done"):
                summary = evt.get("summary")

        assert len(events) == 2
        assert events[0]["url"] == "live@gmail.com"
        assert events[0]["status"] == "active"
        assert events[0]["platform"] == "gmail"

        assert events[1]["url"] == "dead@gmail.com"
        assert events[1]["status"] == "taken_down"
        assert events[1]["platform"] == "gmail"

        assert summary["total"] == 2
        assert summary["active"] == 1
        assert summary["taken_down"] == 1
