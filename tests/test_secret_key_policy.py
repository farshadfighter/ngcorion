"""SECRET_KEY must be a real key: not a placeholder published in this repository, and at least
32 characters (app/core/config.py: require_secure_secret_key)."""
import pytest

from app.core import config


@pytest.mark.parametrize("key", [
    "your-secret-key-here-change-in-production-min-32-chars",   # config.py default
    "change-this-to-a-random-32-character-string",              # .env.example
    "short-key",
    "x" * 31,
])
def test_weak_or_published_keys_stop_the_start(monkeypatch, key):
    monkeypatch.setattr(config.settings, "SECRET_KEY", key)
    with pytest.raises(RuntimeError):
        config.require_secure_secret_key()


def test_a_real_key_is_accepted(monkeypatch):
    key = "4f1c" * 16   # what `openssl rand -hex 32` produces: 64 characters
    monkeypatch.setattr(config.settings, "SECRET_KEY", key)
    assert config.require_secure_secret_key() == key
