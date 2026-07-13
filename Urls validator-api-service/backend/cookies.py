"""
Cookie Manager — Enterprise URL Validation Engine.

Reads and writes cookies from/to cookies.json.
Provides cookie headers for HTTP requests.
"""

import json
import os
from typing import Any

COOKIE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cookies.json"
)


def load_all_cookies() -> dict[str, list[dict]]:
    """Load all cookies from cookies.json."""
    default_structure = {
        "facebook": [],
        "linkedin": [],
        "instagram": [],
        "x": []
    }
    
    if not os.path.exists(COOKIE_FILE):
        return default_structure
        
    try:
        with open(COOKIE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure it has all required keys
            cookies = data.get("cookies", {})
            for key in default_structure:
                if key not in cookies or not isinstance(cookies[key], list):
                    cookies[key] = []
            return cookies
    except Exception:
        return default_structure


def save_all_cookies(cookies_dict: dict[str, list[dict]]) -> None:
    """Save cookies dictionary to cookies.json."""
    try:
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            json.dump({"cookies": cookies_dict}, f, indent=2)
    except Exception as e:
        from backend.logger import get_logger
        get_logger().error(f"[COOKIES] Failed to save cookies: {e}")


def get_cookie_header_string(platform: str) -> str | None:
    """
    Get the formatted Cookie header string for the given platform.
    
    Returns 'name1=value1; name2=value2' or None if no cookies exist.
    """
    cookies = load_all_cookies()
    platform_cookies = cookies.get(platform, [])
    
    if not platform_cookies:
        return None
        
    parts = []
    for c in platform_cookies:
        name = c.get("name")
        value = c.get("value")
        if name and value:
            parts.append(f"{name}={value}")
            
    return "; ".join(parts) if parts else None
