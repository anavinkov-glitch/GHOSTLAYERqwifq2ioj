"""Configuration.

Everything can be overridden with an environment variable, and everything
has a sane default, so ``python run.py`` works on a clean checkout with no
setup at all.
"""

from __future__ import annotations

import os
import secrets


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _secret_key() -> str:
    """A stable secret without asking the user to configure one.

    Generated once and kept in the instance folder, so sessions survive a
    restart during a demo. In production this comes from the environment.
    """
    from_env = os.environ.get("GHOSTLAYER_SECRET_KEY")
    if from_env:
        return from_env
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    path = os.path.join(INSTANCE_DIR, "secret_key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
            if value:
                return value
    value = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


class Config:
    SECRET_KEY = _secret_key()
    DATABASE = os.environ.get("GHOSTLAYER_DB", os.path.join(INSTANCE_DIR, "ghostlayer.db"))
    SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

    MAX_CONTENT_LENGTH = int(os.environ.get("GHOSTLAYER_MAX_UPLOAD_MB", "20")) * 1024 * 1024
    FREE_SCANS = int(os.environ.get("GHOSTLAYER_FREE_SCANS", "1"))
    RETAIN_REPORTS = int(os.environ.get("GHOSTLAYER_RETAIN_REPORTS", "60"))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 14

    # The uploaded file is never written to disk. It is scanned in memory
    # and dropped; only the report is stored.
    STORE_UPLOADS = False
