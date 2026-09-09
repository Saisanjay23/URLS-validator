"""
Screenshot evidence + OCR helpers.

Two independent, feature-flagged capabilities, both used only from the browser
(Playwright) layer so the fast HTTP path is never touched:

  ENABLE_SCREENSHOT_CAPTURE — save a viewable PNG of the rendered page to
      SCREENSHOT_DIR under a deterministic per-URL name, served back to the UI
      at /evidence/<file> for hover previews and kept as takedown evidence.
  ENABLE_SCREENSHOT_OCR     — read text off the rendered pixels (pytesseract)
      inside the Playwright fallback so removal notices that are JS-injected or
      drawn as images (invisible to HTML phrase-matching) are still detected.

Everything degrades gracefully: missing dependencies or any runtime error yield
an empty/no-op result and a logged warning, never an exception into a checker.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import os

from backend import config
from backend.logger import get_logger

logger = get_logger()

try:
    import pytesseract
    from PIL import Image
    HAS_OCR = True
except Exception:
    HAS_OCR = False


def evidence_paths(platform: str, url: str) -> tuple[str, str]:
    """
    Deterministic (disk_path, web_path) for a URL's screenshot.

    The name is stable per URL (sha1 of the URL), so re-captures overwrite the
    previous shot and the UI can always reference /evidence/<file>.
    """
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
    filename = f"{platform}_{digest}.png"
    disk_path = os.path.join(config.SCREENSHOT_DIR, filename)
    web_path = f"/evidence/{filename}"
    return disk_path, web_path


def save_png_bytes(png: bytes, disk_path: str) -> None:
    """Write PNG bytes to disk, creating the evidence dir if needed."""
    os.makedirs(config.SCREENSHOT_DIR, exist_ok=True)
    with open(disk_path, "wb") as f:
        f.write(png)


def _ocr_bytes(png: bytes) -> str:
    """Run OCR on PNG bytes and return the extracted text (blocking)."""
    img = Image.open(io.BytesIO(png))
    return pytesseract.image_to_string(img)


async def ocr_page(page) -> str:
    """
    OCR the rendered pixels of a live Playwright page. Returns lowercased text,
    or "" when OCR is disabled/unavailable or anything fails. Never raises.
    """
    if not config.ENABLE_SCREENSHOT_OCR:
        return ""
    if not HAS_OCR:
        logger.warning(
            "[SCREENSHOT] OCR enabled but pytesseract/Pillow unavailable "
            "(pip install pytesseract Pillow + install the tesseract binary)"
        )
        return ""
    try:
        png = await page.screenshot(full_page=False)
        text = await asyncio.to_thread(_ocr_bytes, png)
        return text or ""
    except Exception as e:
        logger.warning(f"[SCREENSHOT] OCR failed: {str(e)[:80]}")
        return ""
