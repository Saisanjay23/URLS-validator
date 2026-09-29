import json
import os
import pytest
from backend import cookies


def test_load_all_cookies_from_env_json(monkeypatch):
    test_data = {
        "cookies": {
            "facebook": [{"name": "c_user", "value": "12345"}],
            "instagram": [{"name": "sessionid", "value": "abcde"}],
            "linkedin": [],
            "x": []
        }
    }
    monkeypatch.setenv("COOKIES_JSON", json.dumps(test_data))
    loaded = cookies.load_all_cookies()
    assert loaded["facebook"] == [{"name": "c_user", "value": "12345"}]
    assert loaded["instagram"] == [{"name": "sessionid", "value": "abcde"}]
    assert loaded["linkedin"] == []
    assert loaded["x"] == []


def test_get_cookie_header_string_from_env(monkeypatch):
    test_data = {
        "cookies": {
            "facebook": [
                {"name": "c_user", "value": "12345"},
                {"name": "xs", "value": "token_abc"}
            ]
        }
    }
    monkeypatch.setenv("COOKIES_JSON", json.dumps(test_data))
    header = cookies.get_cookie_header_string("facebook")
    assert header == "c_user=12345; xs=token_abc"
    assert cookies.get_cookie_header_string("nonexistent") is None


def test_load_all_cookies_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("COOKIES_JSON", raising=False)
    monkeypatch.delenv("URLCHECK_COOKIES_JSON", raising=False)
    non_existent = str(tmp_path / "does_not_exist.json")
    monkeypatch.setattr(cookies, "COOKIE_FILE", non_existent)
    
    loaded = cookies.load_all_cookies()
    assert "facebook" in loaded
    assert "instagram" in loaded
    assert "linkedin" in loaded
    assert "x" in loaded
    assert loaded["facebook"] == []
