"""Ghostlayer — find the text in a PDF that was written for a model."""

from __future__ import annotations

import logging
import os

from flask import Flask

from .config import Config

__version__ = "1.0.0"


def create_app(config_object: type[Config] = Config) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    logging.basicConfig(
        level=os.environ.get("GHOSTLAYER_LOG", "INFO").upper(),
        format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
    )

    from . import db as database

    database.init_app(app)

    from . import api, auth, views

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(api.bp)
    views.register_error_handlers(app)

    _register_filters(app)

    @app.context_processor
    def inject_globals():
        return {"app_version": __version__}

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    return app


def _register_filters(app: Flask) -> None:
    @app.template_filter("pct")
    def pct(value: float) -> str:
        try:
            return f"{float(value) * 100:.0f}%"
        except (TypeError, ValueError):
            return "0%"

    @app.template_filter("bytesize")
    def bytesize(value: int) -> str:
        try:
            value = int(value)
        except (TypeError, ValueError):
            return "0 B"
        if value < 1024:
            return f"{value} B"
        if value < 1024 * 1024:
            return f"{value / 1024:.0f} KB"
        return f"{value / (1024 * 1024):.1f} MB"

    @app.template_filter("visible")
    def visible(value: str) -> str:
        """Make invisible characters visible, for the evidence panel."""
        from .scanner.patterns import BIDI_CHARS, INVISIBLE_CHARS, TAG_RANGE

        out = []
        for ch in value or "":
            code = ord(ch)
            if ch in INVISIBLE_CHARS:
                out.append("\u2423")
            elif ch in BIDI_CHARS:
                out.append("\u21c4")
            elif TAG_RANGE[0] <= code <= TAG_RANGE[1]:
                out.append(chr(code - 0xE0000))
            elif code < 32 and ch not in "\n\t":
                out.append("\u2400")
            else:
                out.append(ch)
        return "".join(out)
