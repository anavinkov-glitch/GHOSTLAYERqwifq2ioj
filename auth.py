"""Accounts.

Sessions are signed cookies; passwords are hashed with the platform
default (PBKDF2-SHA256 via Werkzeug). Guest scans run before sign-up are
carried over to the new account so nobody loses the report they were
looking at.
"""

from __future__ import annotations

import functools
import re
import time

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from . import db

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
MIN_PASSWORD = 8


# --------------------------------------------------------------------------
# Request plumbing
# --------------------------------------------------------------------------


@bp.before_app_request
def load_user() -> None:
    user_id = session.get("user_id")
    g.user = db.user_by_id(user_id) if user_id else None
    if g.user is None and user_id is not None:
        session.pop("user_id", None)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Sign in to see that page.", "info")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# Free-scan accounting
# --------------------------------------------------------------------------


def free_scans_left() -> int:
    """How many scans a signed-out visitor has left.

    Signed-in users are unlimited; this only governs the try-before-you-
    sign-up path.
    """
    if g.get("user"):
        return 10 ** 6
    allowance = current_app.config["FREE_SCANS"]
    return max(0, allowance - int(session.get("guest_scans", 0)))


def record_guest_scan(token: str) -> None:
    session["guest_scans"] = int(session.get("guest_scans", 0)) + 1
    tokens = list(session.get("guest_tokens", []))
    tokens.append(token)
    session["guest_tokens"] = tokens[-10:]
    session.modified = True


# --------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------


def _validate(email: str, password: str, confirm: str | None = None) -> list[str]:
    errors: list[str] = []
    if not EMAIL_RE.match(email or ""):
        errors.append("That email address does not look right.")
    if len(password or "") < MIN_PASSWORD:
        errors.append(f"Use at least {MIN_PASSWORD} characters for the password.")
    if confirm is not None and password != confirm:
        errors.append("The two passwords do not match.")
    return errors


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("main.scan"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        name = (request.form.get("display_name") or "").strip() or None

        errors = _validate(email, password, confirm)
        if not errors and db.user_by_email(email):
            errors.append("There is already an account on that address.")

        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("register.html", email=email, display_name=name or "")

        guest_tokens = list(session.get("guest_tokens", []))
        user_id = db.create_user(email, generate_password_hash(password), name)
        session.clear()
        session["user_id"] = user_id
        session.permanent = True

        claimed = db.claim_guest_scans(guest_tokens, user_id)
        if claimed:
            flash("Account created. Your earlier scan was saved to it.", "success")
        else:
            flash("Account created. Scanning is unlimited from here.", "success")
        return redirect(url_for("main.scan"))

    return render_template("register.html", email="", display_name="")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.scan"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = db.user_by_email(email)

        if user is None or not check_password_hash(user["password_hash"], password):
            # One message for both cases: naming which half was wrong tells
            # an attacker which addresses have accounts.
            flash("That email and password do not match an account.", "error")
            return render_template("login.html", email=email)

        guest_tokens = list(session.get("guest_tokens", []))
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        db.touch_user(user["id"])
        db.claim_guest_scans(guest_tokens, user["id"])

        destination = request.args.get("next") or request.form.get("next")
        if destination and destination.startswith("/") and not destination.startswith("//"):
            return redirect(destination)
        return redirect(url_for("main.scan"))

    return render_template("login.html", email="")


@bp.route("/logout")
def logout():
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST" and request.form.get("action") == "rotate_key":
        db.rotate_api_key(g.user["id"])
        flash("New API key issued. The old one stopped working immediately.", "success")
        return redirect(url_for("auth.account"))

    user = db.user_by_id(g.user["id"])
    return render_template(
        "account.html",
        account=user,
        stats=db.user_stats(g.user["id"]),
        member_since=time.strftime("%d %B %Y", time.localtime(user["created_at"])),
    )
