"""A small REST API.

The point of the API is that a scanner belongs in front of the pipeline,
not beside it. An applicant-tracking system posts the file here before it
hands anything to a model.
"""

from __future__ import annotations

import functools

from flask import Blueprint, current_app, g, jsonify, request

from . import db
from .scanner import DETECTOR_INFO, scan_bytes

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def api_key_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key", "")
        user = db.user_by_api_key(key)
        if user is None:
            return jsonify(
                {
                    "ok": False,
                    "error": "Missing or unrecognised API key.",
                    "hint": "Send it in the X-API-Key header. Your key is on the account page.",
                }
            ), 401
        g.api_user = user
        return view(*args, **kwargs)

    return wrapped


@bp.get("/health")
def health():
    return jsonify({"ok": True, "service": "ghostlayer", "detectors": len(DETECTOR_INFO)})


@bp.get("/detectors")
def detectors():
    return jsonify(
        {
            "ok": True,
            "count": len(DETECTOR_INFO),
            "detectors": [{"name": k, "describes": v} for k, v in DETECTOR_INFO.items()],
        }
    )


@bp.post("/scan")
@api_key_required
def scan():
    upload = request.files.get("file") or request.files.get("document")
    if upload is None:
        if not request.data:
            return jsonify({"ok": False, "error": "Attach a PDF as 'file', or post the bytes directly."}), 400
        data = request.data
        filename = request.headers.get("X-Filename", "upload.pdf")
    else:
        data = upload.read()
        filename = upload.filename or "upload.pdf"

    limit = current_app.config["MAX_CONTENT_LENGTH"]
    if len(data) > limit:
        return jsonify({"ok": False, "error": f"File exceeds the {limit} byte limit."}), 413
    if not data:
        return jsonify({"ok": False, "error": "Empty request body."}), 400

    include_pages = request.args.get("pages", "0") in {"1", "true", "yes"}
    result = scan_bytes(data, filename=filename, render=include_pages)

    token = db.save_scan(g.api_user["id"], result, source="api")
    result["token"] = token

    if not include_pages:
        # Page images and per-run text make the payload large; a pipeline
        # integration only needs the verdict and the findings.
        result = {k: v for k, v in result.items() if k != "pages"}

    status = 200 if result.get("ok") else 422
    return jsonify(result), status


@bp.get("/scan/<token>")
@api_key_required
def fetch(token: str):
    import json

    row = db.scan_by_token(token)
    if row is None or row["user_id"] != g.api_user["id"]:
        return jsonify({"ok": False, "error": "No report with that token on this account."}), 404
    return jsonify(json.loads(row["report"]))


@bp.get("/scans")
@api_key_required
def listing():
    rows = db.scans_for_user(g.api_user["id"], limit=100)
    return jsonify(
        {
            "ok": True,
            "count": len(rows),
            "scans": [
                {
                    "token": r["token"],
                    "filename": r["filename"],
                    "score": r["score"],
                    "verdict": r["verdict"],
                    "findings": r["findings"],
                    "source": r["source"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ],
        }
    )
