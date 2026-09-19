"""The pages people actually use."""

from __future__ import annotations

import io
import json
import os
import time

from flask import (
    Blueprint, Response, abort, current_app, flash, g, redirect,
    render_template, request, send_file, session, url_for
)

from . import db
from .auth import free_scans_left, login_required, record_guest_scan
from .scanner import DETECTOR_INFO, scan_bytes
from .scanner.core import MAX_PAGES

bp = Blueprint("main", __name__)

SAMPLES = [
    {
        "file": "poisoned_resume.pdf",
        "name": "Poisoned resume",
        "blurb": "Eight hiding techniques in one application. The attack as it actually appears.",
    },
    {
        "file": "poisoned_paper.pdf",
        "name": "Poisoned paper",
        "blurb": "A conference submission written at the reviewer's AI rather than the reviewer.",
    },
    {
        "file": "poisoned_invoice.pdf",
        "name": "Look-alike invoice",
        "blurb": "Character-level tricks: zero-width splits, a spoofed domain, smuggled ASCII.",
    },
    {
        "file": "clean_resume.pdf",
        "name": "Clean resume",
        "blurb": "The control. Nothing hidden, and the scanner should say so.",
    },
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _report_for(token: str) -> tuple[dict, object]:
    row = db.scan_by_token(token)
    if row is None:
        abort(404)
    owner = row["user_id"]
    if owner is not None and (g.user is None or g.user["id"] != owner):
        abort(403)
    if owner is None and token not in session.get("guest_tokens", []):
        # A guest report is only visible from the session that produced it.
        if g.user is None:
            abort(403)
    return json.loads(row["report"]), row


def _run_scan(data: bytes, filename: str, source: str = "web") -> tuple[dict, str]:
    result = scan_bytes(data, filename=filename)
    user_id = g.user["id"] if g.user else None
    token = db.save_scan(user_id, result, source=source)
    if g.user is None:
        record_guest_scan(token)
    return result, token


def _human_size(count: int) -> str:
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.0f} KB"
    return f"{count / (1024 * 1024):.1f} MB"


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


@bp.route("/")
def index():
    if g.user:
        return redirect(url_for("main.scan"))
    return render_template(
        "index.html",
        samples=SAMPLES,
        detectors=DETECTOR_INFO,
        stats=db.platform_stats(),
        free_left=free_scans_left(),
    )


@bp.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        if free_scans_left() <= 0:
            flash("That was your free scan. Create an account to keep going.", "gate")
            return redirect(url_for("auth.register"))

        upload = request.files.get("document")
        if upload is None or not upload.filename:
            flash("Choose a PDF to scan.", "error")
            return redirect(url_for("main.scan"))

        data = upload.read()
        if not data:
            flash("That file is empty.", "error")
            return redirect(url_for("main.scan"))

        limit = current_app.config["MAX_CONTENT_LENGTH"]
        if len(data) > limit:
            flash(f"Files are limited to {_human_size(limit)}.", "error")
            return redirect(url_for("main.scan"))

        result, token = _run_scan(data, upload.filename)
        if not result["ok"]:
            flash(result["error"], "error")
        return redirect(url_for("main.report", token=token))

    return render_template(
        "scan.html",
        samples=SAMPLES,
        free_left=free_scans_left(),
        max_mb=current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
        recent=db.scans_for_user(g.user["id"], limit=5) if g.user else [],
    )


@bp.route("/scan/sample/<path:name>", methods=["POST"])
def scan_sample(name: str):
    if free_scans_left() <= 0:
        flash("That was your free scan. Create an account to keep going.", "gate")
        return redirect(url_for("auth.register"))

    safe = os.path.basename(name)
    if safe not in {s["file"] for s in SAMPLES}:
        abort(404)
    path = os.path.join(current_app.config["SAMPLES_DIR"], safe)
    if not os.path.exists(path):
        flash("The sample files are missing. Run samples/make_samples.py to build them.", "error")
        return redirect(url_for("main.scan"))

    with open(path, "rb") as fh:
        data = fh.read()
    _result, token = _run_scan(data, safe, source="sample")
    return redirect(url_for("main.report", token=token))


@bp.route("/report/<token>")
def report(token: str):
    result, row = _report_for(token)
    return render_template(
        "report.html",
        r=result,
        token=token,
        row=row,
        created=time.strftime("%d %b %Y, %H:%M", time.localtime(row["created_at"])),
        size=_human_size(row["bytes"]),
        max_pages=MAX_PAGES,
    )


@bp.route("/report/<token>.json")
def report_json(token: str):
    result, _row = _report_for(token)
    payload = json.dumps(result, indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="ghostlayer-{token}.json"'},
    )


@bp.route("/report/<token>/text")
def report_text(token: str):
    """The extracted text exactly as a model would receive it."""
    result, _row = _report_for(token)
    lines: list[str] = []
    for page in result.get("pages", []):
        lines.append(f"----- page {page['number']} -----")
        for run in page.get("model_view", []):
            mark = "  [HIDDEN] " if run["hidden"] else "           "
            lines.append(mark + run["text"])
        lines.append("")
    body = "\n".join(lines)
    return Response(
        body,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ghostlayer-{token}.txt"'},
    )


@bp.route("/report/<token>/delete", methods=["POST"])
@login_required
def report_delete(token: str):
    if db.delete_scan(token, g.user["id"]):
        flash("Report deleted.", "info")
    return redirect(url_for("main.history"))


@bp.route("/history")
@login_required
def history():
    rows = db.scans_for_user(g.user["id"], limit=100)
    items = [
        {
            **dict(row),
            "when": time.strftime("%d %b, %H:%M", time.localtime(row["created_at"])),
            "size": _human_size(row["bytes"]),
        }
        for row in rows
    ]
    return render_template("history.html", items=items, stats=db.user_stats(g.user["id"]))


@bp.route("/how-it-works")
def how_it_works():
    return render_template("how.html", detectors=DETECTOR_INFO, samples=SAMPLES)


# --------------------------------------------------------------------------
# Error pages
# --------------------------------------------------------------------------


def register_error_handlers(app) -> None:
    @app.errorhandler(403)
    def forbidden(_exc):
        return render_template(
            "error.html",
            code="403",
            headline="That report belongs to someone else",
            body="Reports are private to the account that ran them. Sign in with that account to open it.",
        ), 403

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template(
            "error.html",
            code="404",
            headline="Nothing here",
            body="The page or report you asked for does not exist. It may have been deleted.",
        ), 404

    @app.errorhandler(413)
    def too_large(_exc):
        limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_template(
            "error.html",
            code="413",
            headline="That file is too big",
            body=f"Uploads are capped at {limit} MB. Split the document or raise the limit in config.py.",
        ), 413

    @app.errorhandler(500)
    def server_error(_exc):
        return render_template(
            "error.html",
            code="500",
            headline="The scan broke",
            body="Something failed on our side rather than in your file. Try again, and if it keeps "
                 "happening the console output will say what went wrong.",
        ), 500
