"""
Email Verification Module — Enterprise SMTP/DNS Probe.

Verifies whether an email address is active, non-existent / taken down,
or uncertain without sending any actual emails:
1. Normalizes email address and validates syntax.
2. Performs DNS MX lookup to locate mail exchange servers.
3. Performs an asynchronous SMTP handshake (EHLO -> MAIL FROM -> RCPT TO).
4. Evaluates recipient status from server response (250 OK vs 550 NoSuchUser).
5. Gracefully handles network timeouts, blocked port 25, and greylisting.
"""

import asyncio
import re
import socket
from typing import Any

from backend import config
from backend.logger import logger
from backend.url_utils import detect_email_provider, normalize_email

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


async def resolve_mx_records(domain: str) -> list[str]:
    """Resolve mail exchange (MX) hostnames for a domain, sorted by priority.

    Falls back to direct domain A/AAAA record if no MX records are published.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return []

    if _HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4.0
            resolver.lifetime = 4.0
            answers = await asyncio.to_thread(resolver.resolve, domain, "MX")
            sorted_records = sorted(answers, key=lambda r: r.preference)
            hosts = [str(r.exchange).rstrip(".") for r in sorted_records if str(r.exchange).strip(".")]
            if hosts:
                return hosts
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            logger.debug(f"[EMAIL_CHECKER] DNS MX lookup failed for {domain}: {e}")

    # Fallback via system socket / getaddrinfo
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(domain, 25, type=socket.SOCK_STREAM)
        if addrinfo:
            return [domain]
    except Exception as e:
        logger.debug(f"[EMAIL_CHECKER] Fallback host resolution failed for {domain}: {e}")

    return []


async def _read_smtp_response(reader: asyncio.StreamReader, timeout: float = 5.0) -> tuple[int, str]:
    """Read a standard or multi-line SMTP response code and message."""
    lines: list[str] = []
    code = 0
    while True:
        line_bytes = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line_bytes:
            break
        line = line_bytes.decode("utf-8", errors="replace").strip()
        lines.append(line)
        if len(line) >= 3 and line[:3].isdigit():
            code = int(line[:3])
            # RFC 5321: hyphen at index 3 indicates continuation line, space indicates final line
            if len(line) == 3 or line[3] != "-":
                break
        else:
            break
    full_text = " ".join(lines)
    # Clean up excess internal codes from multi-line text
    clean_text = re.sub(r"\b\d{3}[ -]", "", full_text).strip()
    return code, clean_text or full_text


async def probe_smtp_mailbox(mx_host: str, email: str, timeout: float) -> tuple[int, str]:
    """Perform SMTP RCPT TO probe on the given MX host.

    Returns (status_code, response_message).
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(mx_host, 25),
        timeout=timeout,
    )
    try:
        # 1. Read initial banner (220)
        banner_code, banner_msg = await _read_smtp_response(reader, timeout=timeout)
        if banner_code >= 400:
            return banner_code, f"Banner rejected: {banner_msg}"

        # 2. Send EHLO
        helo_domain = config.EMAIL_HELO_DOMAIN
        writer.write(f"EHLO {helo_domain}\r\n".encode())
        await writer.drain()
        ehlo_code, ehlo_msg = await _read_smtp_response(reader, timeout=timeout)
        if ehlo_code >= 400:
            # Fallback to standard HELO if EHLO not supported
            writer.write(f"HELO {helo_domain}\r\n".encode())
            await writer.drain()
            ehlo_code, ehlo_msg = await _read_smtp_response(reader, timeout=timeout)
            if ehlo_code >= 400:
                return ehlo_code, f"HELO rejected: {ehlo_msg}"

        # 3. Send MAIL FROM
        writer.write(f"MAIL FROM:<check@{helo_domain}>\r\n".encode())
        await writer.drain()
        mail_code, mail_msg = await _read_smtp_response(reader, timeout=timeout)
        if mail_code >= 400:
            return mail_code, f"MAIL FROM rejected: {mail_msg}"

        # 4. Send RCPT TO
        writer.write(f"RCPT TO:<{email}>\r\n".encode())
        await writer.drain()
        rcpt_code, rcpt_msg = await _read_smtp_response(reader, timeout=timeout)

        # 5. Send QUIT cleanly
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception:
            pass

        return rcpt_code, rcpt_msg
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def check_email(raw_email: str) -> dict[str, Any]:
    """Verify an email address via DNS MX resolution and SMTP probe.

    Returns a standardized dictionary matching fast_checker results:
    - status: "active" | "taken_down" | "uncertain"
    - platform: "gmail" | "outlook" | "yahoo" | "email"
    - confidence: int (0-100)
    - reason: str
    - http_code: int | None (SMTP response code)
    - engine: "email_smtp"
    """
    normalized = normalize_email(raw_email)
    platform = detect_email_provider(raw_email)

    if not normalized:
        return {
            "type": "result",
            "url": raw_email,
            "platform": platform,
            "status": "uncertain",
            "confidence": 0,
            "reason": f"Invalid email format: '{raw_email}'",
            "http_code": None,
            "engine": "email_smtp",
        }

    domain = normalized.split("@", 1)[1]

    # Resolve MX records
    mx_hosts = await resolve_mx_records(domain)
    if not mx_hosts:
        return {
            "type": "result",
            "url": normalized,
            "platform": platform,
            "status": "taken_down",
            "confidence": 95,
            "reason": f"Domain '{domain}' does not exist or has no mail servers configured",
            "http_code": None,
            "engine": "email_smtp",
        }

    # Probe MX hosts (try up to 2 MX hosts in case first is unreachable)
    last_err: str = ""
    timeout = config.EMAIL_SMTP_TIMEOUT

    for mx_host in mx_hosts[:2]:
        try:
            code, msg = await probe_smtp_mailbox(mx_host, normalized, timeout=timeout)

            if code == 250 or code == 251:
                # Active mailbox confirmed
                provider_note = ""
                if platform == "gmail":
                    provider_note = " (Active Google account)"
                return {
                    "type": "result",
                    "url": normalized,
                    "platform": platform,
                    "status": "active",
                    "confidence": 90,
                    "reason": f"Mailbox exists (SMTP {code} OK from {mx_host}){provider_note}",
                    "http_code": code,
                    "engine": "email_smtp",
                }

            if code in (550, 551, 552, 553, 554):
                # Mailbox does not exist / rejected
                clean_reason = msg if msg else "User unknown / mailbox unavailable"
                return {
                    "type": "result",
                    "url": normalized,
                    "platform": platform,
                    "status": "taken_down",
                    "confidence": 95,
                    "reason": f"Mailbox does not exist (SMTP {code}: {clean_reason})",
                    "http_code": code,
                    "engine": "email_smtp",
                }

            if code in (450, 451, 452, 421):
                # Greylisted or rate-limited
                return {
                    "type": "result",
                    "url": normalized,
                    "platform": platform,
                    "status": "uncertain",
                    "confidence": 30,
                    "reason": f"Mail server deferred verification (SMTP {code}: {msg})",
                    "http_code": code,
                    "engine": "email_smtp",
                }

            # Other status codes
            return {
                "type": "result",
                "url": normalized,
                "platform": platform,
                "status": "uncertain",
                "confidence": 20,
                "reason": f"SMTP response code {code}: {msg}",
                "http_code": code,
                "engine": "email_smtp",
            }

        except (asyncio.TimeoutError, TimeoutError):
            last_err = f"Connection to {mx_host}:25 timed out (port 25 may be blocked by network/ISP)"
        except (ConnectionRefusedError, OSError) as e:
            last_err = f"Cannot reach {mx_host}:25 ({e})"
        except Exception as e:
            last_err = f"SMTP probe error on {mx_host}: {e}"

    # If all MX servers failed network connection
    return {
        "type": "result",
        "url": normalized,
        "platform": platform,
        "status": "uncertain",
        "confidence": 0,
        "reason": last_err or "Unable to connect to mail servers",
        "http_code": None,
        "engine": "email_smtp",
    }
