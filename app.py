"""CyberShield's Flask application entry point."""

from functools import wraps
import csv
import hashlib
import hmac
import http.client
import ipaddress
import io
import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from authlib.integrations.flask_client import OAuth
    _OAUTH_IMPORT_ERROR = None
except ImportError as exc:  # Keep local startup usable until dependencies are installed.
    OAuth = None
    _OAUTH_IMPORT_ERROR = str(exc)

from database import INTEGRITY_ERRORS, close_db, get_db, init_db
from detectors import analyze_file, analyze_ip, analyze_logs, analyze_nessus_report, analyze_url
from site_inspector import inspect_public_site
from pdf_reports import build_agent_events_pdf, build_scan_pdf


load_dotenv()
INDIA_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")
GUEST_FREE_SCANS = 4


def risk_level(value):
    """Normalize current and older stored labels to the display scale."""
    return {
        "informational": "Info",
        "unverified": "Info",
        "review": "Low",
        "normal": "Info",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }.get(str(value).lower(), str(value).title())


def ensure_saved_log_summaries(details):
    """Build missing report charts from already-saved parsed log events only."""
    events = details.get("log_events")
    if not isinstance(events, list) or not events:
        return details

    if not details.get("log_severity_counts"):
        counts = {label: 0 for label in ("Info", "Low", "Medium", "High", "Critical", "Unclassified")}
        aliases = {
            "INFO": "Info", "INFORMATIONAL": "Info", "LOW": "Low", "MEDIUM": "Medium",
            "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical", "CRIT": "Critical",
            "ALERT": "Critical", "EMERGENCY": "Critical", "FATAL": "Critical",
        }
        for event in events:
            if not isinstance(event, dict):
                continue
            raw = str(event.get("severity") or "").upper()
            counts[aliases.get(raw, "Unclassified")] += 1
        details["log_severity_counts"] = counts

    if not details.get("cvss_severity_counts"):
        counts = {label: 0 for label in ("None", "Low", "Medium", "High", "Critical")}
        for event in events:
            if not isinstance(event, dict):
                continue
            try:
                score = float(event.get("cvss_base_calculated"))
            except (TypeError, ValueError):
                continue
            if not 0.0 <= score <= 10.0:
                continue
            severity = (
                "None" if score == 0.0 else "Low" if score < 4.0 else
                "Medium" if score < 7.0 else "High" if score < 9.0 else "Critical"
            )
            counts[severity] += 1
        details["cvss_severity_counts"] = counts
        details["cvss_unscored_count"] = len(events) - sum(counts.values())
    return details


def dashboard_analytics(db, user_id=None):
    """Build chart series from real visible scan records without retaining extra data."""
    scope = " WHERE user_hidden_at IS NULL" if user_id is not None else ""
    parameters = (user_id,) if user_id is not None else ()
    if user_id is not None:
        scope += " AND user_id = ?"
    risk_rows = db.execute(
        "SELECT lower(risk) AS risk, COUNT(*) AS count FROM scans" + scope + " GROUP BY lower(risk)",
        parameters,
    ).fetchall()
    module_rows = db.execute(
        "SELECT module, COUNT(*) AS count FROM scans" + scope + " GROUP BY module",
        parameters,
    ).fetchall()

    risk_counts = {label: 0 for label in ("Info", "Low", "Medium", "High", "Critical")}
    for row in risk_rows:
        label = risk_level(row["risk"])
        if label not in risk_counts:
            label = "Low"
        risk_counts[label] += row["count"]
    risk_total = sum(risk_counts.values())
    risk_colors = {"Info": "#34d399", "Low": "#55b8ff", "Medium": "#c58bff", "High": "#ffb84d", "Critical": "#ff5878"}
    risk_data = [
        {"label": label, "count": count, "percent": round(count * 100 / risk_total, 1) if risk_total else 0, "color": risk_colors[label]}
        for label, count in risk_counts.items()
    ]
    stops = []
    degrees = 0.0
    for item in risk_data:
        if item["count"]:
            next_degrees = degrees + item["count"] * 360 / risk_total
            stops.append(f"{item['color']} {degrees:.2f}deg {next_degrees:.2f}deg")
            degrees = next_degrees
    risk_gradient = f"conic-gradient({', '.join(stops)})" if stops else ""

    module_order = ("IP Detection", "URL Scanner", "File Analyzer", "Log Analysis", "Nessus Report")
    module_counts = {name: 0 for name in module_order}
    for row in module_rows:
        name = row["module"]
        module_counts[name] = module_counts.get(name, 0) + row["count"]
    module_total = sum(module_counts.values())
    module_data = [
        {"label": name, "count": count, "percent": round(count * 100 / module_total, 1) if module_total else 0}
        for name, count in module_counts.items()
    ]

    today = datetime.now(INDIA_TIMEZONE).date()
    days = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    first_day = datetime.combine(days[0], datetime.min.time(), tzinfo=INDIA_TIMEZONE)
    cutoff = first_day.astimezone(timezone.utc)
    if current_app.config.get("DATABASE_URL"):
        cutoff_parameter = cutoff
    else:
        cutoff_parameter = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    recent_scope = " WHERE created_at >= ?" + (" AND user_hidden_at IS NULL AND user_id = ?" if user_id is not None else "")
    recent_parameters = (cutoff_parameter, user_id) if user_id is not None else (cutoff_parameter,)
    recent_rows = db.execute(
        "SELECT module, risk, created_at FROM scans" + recent_scope,
        recent_parameters,
    ).fetchall()

    daily = {day: {"total": 0, "review": 0, "high": 0} for day in days}
    for row in recent_rows:
        try:
            local_day = parse_utc_datetime(row["created_at"]).astimezone(INDIA_TIMEZONE).date()
        except (TypeError, ValueError):
            continue
        if local_day not in daily:
            continue
        item = daily[local_day]
        item["total"] += 1
        label = risk_level(row["risk"])
        if label in {"Low", "Medium", "High", "Critical"}:
            item["review"] += 1
        if label in {"High", "Critical"}:
            item["high"] += 1

    max_count = max((values["total"] for values in daily.values()), default=0)
    chart_width, chart_height = 700, 190
    left, right, top, bottom = 40, 688, 14, 157
    x_step = (right - left) / 6

    def series_points(key):
        points = []
        for index, day in enumerate(days):
            count = daily[day][key]
            y = bottom - (count / max_count * (bottom - top) if max_count else 0)
            points.append(f"{left + index * x_step:.1f},{y:.1f}")
        return " ".join(points)

    activity = [
        {"label": day.strftime("%a"), "date": day.strftime("%b %d"), "total": daily[day]["total"], "review": daily[day]["review"], "high": daily[day]["high"], "x": round(left + index * x_step, 1)}
        for index, day in enumerate(days)
    ]
    return {
        "risk_data": risk_data,
        "risk_total": risk_total,
        "risk_gradient": risk_gradient,
        "module_data": module_data,
        "module_total": module_total,
        "activity": activity,
        "activity_series": {"total": series_points("total"), "review": series_points("review"), "high": series_points("high")},
        "activity_max": max_count,
        "chart_width": chart_width,
        "chart_height": chart_height,
        "chart_left": left,
        "chart_right": right,
        "chart_top": top,
        "chart_bottom": bottom,
    }


def persisted_analysis_details(result):
    """Keep derived findings only; never persist uploaded bytes or pasted log text."""
    allowed = {
        "label", "explanation", "site_explanation", "redirect_chain", "indicators", "recommendations",
        "facts", "line_count", "counts", "event_categories", "log_events",
        "log_severity_counts", "cvss_severity_counts", "cvss_unscored_count",
        "nessus_report_name", "nessus_findings", "nessus_counts", "nessus_total_items",
        "file_type", "size", "sha256", "findings", "analysis_scope",
    }
    return {key: value for key, value in result.items() if key in allowed}


def analyze_url_live(value):
    result = analyze_url(value)
    result["facts"]["Threat reputation"] = "Not queried — no live threat-intelligence provider is connected."
    result["facts"]["CVSS Base score"] = "Not applicable — this check does not identify CVE-based software vulnerabilities."
    try:
        site = inspect_public_site(value)
    except (OSError, ValueError, http.client.HTTPException):
        result["facts"]["Live website review"] = "Not completed"
        result["indicators"].append("Live page details could not be gathered; the risk label uses local URL checks only.")
        result["site_explanation"] = "The live request did not complete. No page content or reputation data was available for this review."
        result["explanation"] = "CyberShield checked the URL structure locally and attempted a limited read-only request, but the website details could not be gathered. No threat-reputation source was checked."
        result["recommendations"].append("Verify the website address independently before entering sensitive information.")
        return result

    result["facts"].update(site["facts"])
    result["indicators"].extend(site["indicators"])
    result["recommendations"].extend(site["recommendations"])
    result["site_explanation"] = site["explanation"]
    result["explanation"] = "CyberShield checked URL structure and fetched limited public page metadata. It did not compare the URL with threat-intelligence reports, so the findings are not a safety verdict."
    result["redirect_chain"] = site["redirect_chain"]
    if site.get("password_form_over_http"):
        result["risk"] = "High"
        result["label"] = "Password form served without HTTPS"
        result["summary"] = "The page includes a password field but its final destination is not using HTTPS."
        result["recommendations"].insert(0, "Do not enter a password on this page. Verify the correct HTTPS address independently.")
    return result


WINDOWS_AGENT_EVENT_RULES = {
    ("security", 4624): ("Windows sign-in succeeded", None, None),
    ("security", 4625): ("Windows sign-in failed", None, None),
    ("security", 5156): ("Windows Firewall allowed a network connection", None, None),
    ("security", 5157): ("Windows Firewall blocked a network connection", None, None),
    ("security", 1102): ("Windows Security audit log cleared", "High", "The Windows Security audit log was cleared. Review the device and account activity."),
    ("microsoft-windows-windows defender/operational", 1116): ("Microsoft Defender threat detected", "High", "Microsoft Defender reported a threat on this device. Review the threat in Windows Security."),
    ("microsoft-windows-windows defender/operational", 1117): ("Microsoft Defender action recorded", None, None),
}


def _parse_agent_time(value):
    if not isinstance(value, str) or len(value) > 48:
        raise ValueError("Invalid event timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid event timestamp.") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _agent_is_online(last_seen_at, now=None):
    if not last_seen_at:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        seen = last_seen_at if isinstance(last_seen_at, datetime) else datetime.fromisoformat(str(last_seen_at).replace("Z", "+00:00"))
    except ValueError:
        return False
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return timedelta(0) <= now - seen.astimezone(timezone.utc) <= timedelta(seconds=90)


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=load_secret_key(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "cybershield.sqlite3"),
        DATABASE_URL=os.getenv("DATABASE_URL", "").strip(),
        BREVO_API_KEY=os.getenv("BREVO_API_KEY", "").strip(),
        BREVO_SENDER_EMAIL=os.getenv("BREVO_SENDER_EMAIL", "").strip(),
        GOOGLE_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        GOOGLE_CLIENT_SECRET=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
        GOOGLE_REDIRECT_URI=os.getenv("GOOGLE_REDIRECT_URI", "").strip(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    )
    app.teardown_appcontext(close_db)
    init_db(app)
    app.jinja_env.filters["ist_datetime"] = ist_datetime
    app.jinja_env.filters["risk_level"] = risk_level

    oauth = None
    if OAuth is None:
        app.logger.warning(
            "Google OAuth disabled: Authlib could not be imported (%s)",
            _OAUTH_IMPORT_ERROR or "unknown import error",
        )
    else:
        missing_google_oauth = [
            key
            for key in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")
            if not app.config[key]
        ]
        if missing_google_oauth:
            app.logger.warning(
                "Google OAuth disabled: missing or empty environment variable(s): %s",
                ", ".join(missing_google_oauth),
            )
        else:
            oauth = OAuth(app)
    if oauth is not None:
        oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if session.get("user_id") and request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def expire_local_user_scans():
        if app.config.get("DATABASE_URL") or request.endpoint in {"health", "static"}:
            return
        db = get_db()
        db.execute(
            "DELETE FROM scans WHERE user_id IN "
            "(SELECT id FROM users WHERE role = 'user') "
            "AND datetime(created_at) < datetime('now', '-24 hours')"
        )
        db.commit()

    @app.context_processor
    def add_template_helpers():
        user = get_current_user()
        return {
            "csrf_token": csrf_token,
            "current_user": user,
            "guest_scans_remaining": guest_scans_remaining() if user is None else None,
            "google_oauth_enabled": oauth is not None,
        }

    @app.get("/")
    def home():
        if not has_users():
            return redirect(url_for("setup"))
        user = get_current_user()
        if user is None:
            return redirect(url_for("scan_ip"))
        return redirect(url_for("dashboard"))

    @app.get("/auth/google")
    def google_login():
        if not has_users():
            return redirect(url_for("setup"))
        if oauth is None:
            flash("Google sign-in is not configured yet. You can use your email and password meanwhile.", "error")
            return redirect(url_for("login"))
        redirect_uri = app.config["GOOGLE_REDIRECT_URI"] or url_for("google_callback", _external=True, _scheme="https")
        return oauth.google.authorize_redirect(redirect_uri)

    @app.get("/auth/google/callback")
    def google_callback():
        if not has_users():
            return redirect(url_for("setup"))
        if oauth is None:
            return redirect(url_for("login"))
        try:
            token = oauth.google.authorize_access_token()
            profile = token.get("userinfo") or {}
            email = str(profile.get("email", "")).strip().lower()
            email_verified = profile.get("email_verified") is True or str(profile.get("email_verified", "")).lower() == "true"
            if not profile.get("sub") or not email_verified or not valid_email(email):
                flash("Google did not return a verified email address. Please sign in another way.", "error")
                return redirect(url_for("login"))
        except Exception:
            current_app.logger.exception("Google sign-in could not be completed")
            flash("Google sign-in could not be completed. Please try again or use your email and password.", "error")
            return redirect(url_for("login"))

        db = get_db()
        user = db.execute(
            "SELECT id, email, password_hash FROM users WHERE LOWER(email) = LOWER(?)", (email,)
        ).fetchone()
        if user is None:
            try:
                password_hash = generate_password_hash(secrets.token_urlsafe(48))
                cursor = db.execute(
                    "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user') RETURNING id",
                    (email, password_hash),
                )
                user = {"id": cursor.fetchone()["id"], "email": email, "password_hash": password_hash}
                db.commit()
            except INTEGRITY_ERRORS:
                db.rollback()
                user = db.execute(
                    "SELECT id, email, password_hash FROM users WHERE LOWER(email) = LOWER(?)", (email,)
                ).fetchone()
                if user is None:
                    current_app.logger.exception("Google account creation conflicted but no account was found")
                    flash("Account sign-in could not be completed. Please try again.", "error")
                    return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["password_token"] = make_password_token(user["password_hash"])
        session.permanent = True
        return redirect(url_for("dashboard"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if has_users():
            return redirect(url_for("login"))

        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirmation = request.form.get("password_confirmation", "")

            if not valid_email(email):
                flash("Enter a valid email address.", "error")
            elif len(password) < 12:
                flash("Password must be at least 12 characters.", "error")
            elif password != confirmation:
                flash("The passwords do not match.", "error")
            else:
                db = get_db()
                password_hash = generate_password_hash(password)
                cursor = db.execute(
                    "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin') RETURNING id",
                    (email, password_hash),
                )
                record_admin_activity("Administrator account created", email, commit=False,
                                      actor={"email": email, "role": "admin"})
                db.commit()
                session.clear()
                session["user_id"] = cursor.fetchone()["id"]
                session["password_token"] = make_password_token(password_hash)
                flash("Administrator account created successfully.", "success")
                return redirect(url_for("dashboard"))

        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not has_users():
            return redirect(url_for("setup"))
        if get_current_user() is not None:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, email, password_hash, role FROM users WHERE LOWER(email) = LOWER(?)",
                (email,),
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                flash("The email address or password is incorrect.", "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                session["password_token"] = make_password_token(user["password_hash"])
                if user["role"] == "admin":
                    record_admin_activity("Administrator signed in", user["email"], actor=user)
                session.permanent = "remember" in request.form
                return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if not has_users():
            return redirect(url_for("setup"))
        if get_current_user() is not None:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirmation = request.form.get("password_confirmation", "")

            if not valid_email(email):
                flash("Enter a valid email address.", "error")
            elif len(password) < 12:
                flash("Password must be at least 12 characters.", "error")
            elif password != confirmation:
                flash("The passwords do not match.", "error")
            else:
                try:
                    db = get_db()
                    password_hash = generate_password_hash(password)
                    cursor = db.execute(
                        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user') RETURNING id",
                        (email, password_hash),
                    )
                    user_id = cursor.fetchone()["id"]
                    db.commit()
                except INTEGRITY_ERRORS:
                    get_db().rollback()
                    flash("An account with this email address already exists.", "error")
                else:
                    session.clear()
                    session["user_id"] = user_id
                    session["password_token"] = make_password_token(password_hash)
                    flash("Account created successfully.", "success")
                    return redirect(url_for("dashboard"))

        return render_template("register.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            if not valid_email(email):
                flash("Enter the email address for your CyberShield account.", "error")
            elif not brevo_is_configured():
                flash("Email delivery is not configured yet. Ask the administrator to configure email delivery in Render.", "error")
            else:
                account = get_db().execute(
                    "SELECT id, email FROM users WHERE LOWER(email) = LOWER(?)", (email,)
                ).fetchone()
                if account is not None:
                    db = get_db()
                    previous = db.execute(
                        "SELECT requested_at FROM password_reset_codes WHERE user_id = ?",
                        (account["id"],),
                    ).fetchone()
                    now = datetime.now(timezone.utc)
                    if previous is None or now - parse_utc_datetime(previous["requested_at"]) >= timedelta(seconds=60):
                        code = f"{secrets.randbelow(1_000_000):06d}"
                        expires_at = now + timedelta(minutes=10)
                        db.execute(
                            "INSERT INTO password_reset_codes "
                            "(user_id, code_hash, expires_at, attempt_count, requested_at) VALUES (?, ?, ?, 0, ?) "
                            "ON CONFLICT (user_id) DO UPDATE SET code_hash = excluded.code_hash, "
                            "expires_at = excluded.expires_at, attempt_count = 0, requested_at = excluded.requested_at",
                            (account["id"], password_reset_code_digest(account["id"], code),
                             expires_at.isoformat(), now.isoformat()),
                        )
                        db.commit()
                        if not send_password_reset_email(account["email"], code):
                            db.execute("DELETE FROM password_reset_codes WHERE user_id = ?", (account["id"],))
                            db.commit()
                flash("If that email belongs to a CyberShield account, a one-time code will be sent. It expires in 10 minutes. Check spam or ask the administrator to verify email delivery if it does not arrive.", "success")
                return redirect(url_for("reset_password"))
        return render_template("forgot_password.html", page_title="Forgot password")

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            code = request.form.get("code", "").strip()
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("password_confirmation", "")

            if not valid_email(email):
                flash("Enter the email address for your CyberShield account.", "error")
            elif not code.isascii() or not code.isdecimal() or len(code) != 6:
                flash("Enter the 6-digit code from your email.", "error")
            elif len(new_password) < 12:
                flash("New password must be at least 12 characters.", "error")
            elif new_password != confirmation:
                flash("The passwords do not match.", "error")
            else:
                db = get_db()
                account = db.execute(
                    "SELECT users.id, password_reset_codes.code_hash, password_reset_codes.expires_at, "
                    "password_reset_codes.attempt_count FROM users "
                    "JOIN password_reset_codes ON password_reset_codes.user_id = users.id "
                    "WHERE LOWER(users.email) = LOWER(?)",
                    (email,),
                ).fetchone()
                if account is None:
                    flash("The code is invalid or expired. Request a new code and try again.", "error")
                elif account["attempt_count"] >= 5:
                    db.execute("DELETE FROM password_reset_codes WHERE user_id = ?", (account["id"],))
                    db.commit()
                    flash("Too many incorrect code attempts. Request a new code.", "error")
                elif datetime.now(timezone.utc) >= parse_utc_datetime(account["expires_at"]):
                    db.execute("DELETE FROM password_reset_codes WHERE user_id = ?", (account["id"],))
                    db.commit()
                    flash("The code has expired. Request a new one.", "error")
                elif not hmac.compare_digest(
                    account["code_hash"], password_reset_code_digest(account["id"], code)
                ):
                    db.execute(
                        "UPDATE password_reset_codes SET attempt_count = attempt_count + 1 WHERE user_id = ?",
                        (account["id"],),
                    )
                    db.commit()
                    flash("The code is invalid or expired. Request a new code and try again.", "error")
                else:
                    password_hash = generate_password_hash(new_password)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, account["id"]))
                    db.execute("DELETE FROM password_reset_codes WHERE user_id = ?", (account["id"],))
                    db.commit()
                    flash("Password reset successfully. Sign in with your new password.", "success")
                    return redirect(url_for("login"))
        return render_template("reset_password.html", page_title="Reset password")

    @app.post("/logout")
    def logout():
        if not validate_csrf():
            abort(400)
        user = get_current_user()
        if user and user["role"] == "admin":
            record_admin_activity("Administrator signed out", user["email"])
        session.clear()
        return redirect(url_for("login"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        user = get_current_user()

        if request.method == "POST":
            if not validate_csrf():
                abort(400)

            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("password_confirmation", "")
            account = get_db().execute(
                "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
            ).fetchone()

            if account is None or not check_password_hash(account["password_hash"], current_password):
                flash("Your current password is incorrect.", "error")
            elif len(new_password) < 12:
                flash("New password must be at least 12 characters.", "error")
            elif new_password != confirmation:
                flash("The new passwords do not match.", "error")
            elif new_password == current_password:
                flash("Choose a new password different from your current one.", "error")
            else:
                db = get_db()
                new_hash = generate_password_hash(new_password)
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, user["id"]),
                )
                record_admin_activity("Changed administrator password", user["email"],
                                      "Password value was not recorded.", commit=False)
                db.commit()
                was_permanent = session.permanent
                session.clear()
                session["user_id"] = user["id"]
                session["password_token"] = make_password_token(new_hash)
                session.permanent = was_permanent
                flash("Password changed successfully.", "success")
                return redirect(url_for("change_password"))

        return render_template("change_password.html", page_title="Change password")

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user = get_current_user()
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))

        db = get_db()
        user_id = user["id"]
        scan_count = db.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE user_id = ? AND user_hidden_at IS NULL", (user_id,)
        ).fetchone()["count"]
        alert_count = db.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE user_id = ? AND user_hidden_at IS NULL "
            "AND lower(risk) IN ('high', 'critical')",
            (user_id,),
        ).fetchone()["count"]
        recent_scans = db.execute(
            "SELECT id, module, target, risk, created_at FROM scans "
            "WHERE user_id = ? AND user_hidden_at IS NULL ORDER BY id DESC LIMIT 5",
            (user_id,),
        ).fetchall()
        return render_template(
            "user_dashboard.html",
            page_title="My dashboard",
            scan_count=scan_count,
            alert_count=alert_count,
            recent_scans=recent_scans,
            dashboard_data=dashboard_analytics(db, user_id=user_id),
        )

    @app.get("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()
        user_count = db.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'user'").fetchone()["count"]
        scan_count = db.execute("SELECT COUNT(*) AS count FROM scans").fetchone()["count"]
        alert_count = db.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE lower(risk) IN ('high', 'critical')"
        ).fetchone()["count"]
        recent_scans = db.execute(
            "SELECT scans.id, scans.module, scans.target, scans.risk, scans.created_at, users.email "
            "FROM scans JOIN users ON users.id = scans.user_id ORDER BY scans.id DESC LIMIT 8"
        ).fetchall()
        return render_template(
            "admin_dashboard.html",
            page_title="Admin overview",
            user_count=user_count,
            scan_count=scan_count,
            alert_count=alert_count,
            recent_scans=recent_scans,
            dashboard_data=dashboard_analytics(db),
        )

    @app.get("/admin/activity")
    @admin_required
    def admin_activity():
        events = get_db().execute(
            "SELECT actor_email, action, target, details, created_at "
            "FROM admin_activity ORDER BY id DESC LIMIT 200"
        ).fetchall()
        return render_template(
            "admin_activity.html",
            page_title="Admin Activity Log",
            events=events,
        )

    @app.route("/account/agents", methods=["GET", "POST"])
    @login_required
    def manage_agents():
        user = get_current_user()
        db = get_db()
        new_agent_token = None
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            action = request.form.get("action", "create")
            if action != "create":
                abort(400)
            name = request.form.get("name", "").strip()
            if not name or len(name) > 80:
                flash("Enter a device name up to 80 characters long.", "error")
            else:
                active_count = db.execute(
                    "SELECT COUNT(*) AS count FROM endpoint_agents WHERE user_id = ? AND revoked_at IS NULL",
                    (user["id"],),
                ).fetchone()["count"]
                if active_count >= 10:
                    flash("Maximum 10 active Windows agents per account. Revoke one before adding another.", "error")
                else:
                    new_agent_token = secrets.token_urlsafe(32)
                    token_hash = hashlib.sha256(new_agent_token.encode("utf-8")).hexdigest()
                    db.execute(
                        "INSERT INTO endpoint_agents (user_id, name, token_hash) VALUES (?, ?, ?)",
                        (user["id"], name, token_hash),
                    )
                    db.commit()
        agents = db.execute(
            "SELECT id, name, created_at, last_seen_at, revoked_at "
            "FROM endpoint_agents WHERE user_id = ? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
        agents = [dict(agent) | {"online": _agent_is_online(agent["last_seen_at"])} for agent in agents]
        return render_template(
            "endpoint_agents.html",
            page_title="Windows Agents",
            agents=agents,
            new_agent_token=new_agent_token,
        )

    @app.post("/account/agents/<int:agent_id>/revoke")
    @login_required
    def revoke_agent(agent_id):
        if not validate_csrf():
            abort(400)
        user = get_current_user()
        db = get_db()
        db.execute(
            "UPDATE endpoint_agents SET revoked_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
            (agent_id, user["id"]),
        )
        db.commit()
        flash("Agent access revoked. Remove the agent from that Windows device too.", "success")
        return redirect(url_for("manage_agents"))

    @app.get("/account/agents/windows-agent.ps1")
    @login_required
    def download_windows_agent():
        agent_path = Path(app.root_path) / "agent" / "windows_agent.ps1"
        return send_file(agent_path, as_attachment=True, download_name="cybershield-windows-agent.ps1", mimetype="text/plain")

    @app.get("/account/agents/report.pdf")
    @login_required
    def download_agent_event_report():
        user = get_current_user()
        db = get_db()
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        cutoff_parameter = cutoff if current_app.config.get("DATABASE_URL") else cutoff.strftime("%Y-%m-%d %H:%M:%S")
        where = "events.created_at >= ?"
        parameters = [cutoff_parameter]
        if user["role"] != "admin":
            where += " AND agents.user_id = ?"
            parameters.append(user["id"])
        total_count = db.execute(
            "SELECT COUNT(*) AS count FROM endpoint_events AS events "
            "JOIN endpoint_agents AS agents ON agents.id = events.agent_id WHERE " + where,
            tuple(parameters),
        ).fetchone()["count"]
        rows = db.execute(
            "SELECT events.source_ref, events.channel, events.event_time, events.event_id, events.event_name, "
            "events.source_ip, events.source_port, events.destination_ip, events.destination_port, "
            "events.network_protocol, events.network_direction, events.alert_level, events.alert_text, "
            "agents.name AS agent_name, users.email AS account_email "
            "FROM endpoint_events AS events JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
            "JOIN users ON users.id = agents.user_id WHERE " + where +
            " ORDER BY events.created_at DESC, events.id DESC LIMIT 501",
            tuple(parameters),
        ).fetchall()
        report_events = []
        for row in rows[:500]:
            event_time = parse_utc_datetime(row["event_time"])
            item = {
                "source_ref": row["source_ref"],
                "channel": row["channel"],
                "record_id": str(row["source_ref"]).rsplit(":", 1)[-1],
                "event_time_ist": event_time.astimezone(INDIA_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S IST"),
                "event_id": row["event_id"],
                "event_name": row["event_name"],
                "source_ip": row["source_ip"],
                "source_port": row["source_port"],
                "destination_ip": row["destination_ip"],
                "destination_port": row["destination_port"],
                "network_protocol": row["network_protocol"],
                "network_direction": row["network_direction"],
                "alert_level": row["alert_level"],
                "alert_text": row["alert_text"],
                "agent_name": row["agent_name"],
            }
            if user["role"] == "admin":
                item["account_email"] = row["account_email"]
            report_events.append(item)
        generated_at = datetime.now(INDIA_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S IST")
        report = build_agent_events_pdf(
            report_events, generated_at, "Previous 7 days", total_count,
            admin_view=user["role"] == "admin",
        )
        filename = f"cybershield-windows-events-{datetime.now(INDIA_TIMEZONE):%Y%m%d-%H%M%S}.pdf"
        return send_file(report, mimetype="application/pdf", as_attachment=True, download_name=filename)

    @app.get("/api/agent/dashboard")
    @login_required
    def agent_dashboard_data():
        user = get_current_user()
        db = get_db()
        if user["role"] == "admin":
            agents = db.execute(
                "SELECT id, last_seen_at FROM endpoint_agents WHERE revoked_at IS NULL"
            ).fetchall()
            rows = db.execute(
                "SELECT events.id, events.source_ref, events.channel, events.event_time, events.event_id, events.event_name, events.source_ip, events.source_port, "
                "events.destination_ip, events.destination_port, events.network_protocol, events.network_direction, "
                "events.alert_level, events.alert_text, agents.name AS agent_name, users.email AS account_email "
                "FROM endpoint_events AS events JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                "JOIN users ON users.id = agents.user_id WHERE agents.revoked_at IS NULL "
                "ORDER BY events.id DESC LIMIT 20"
            ).fetchall()
            if current_app.config.get("DATABASE_URL"):
                alert_count = db.execute(
                    "SELECT COUNT(*) AS count FROM endpoint_events AS events "
                    "JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                    "WHERE agents.revoked_at IS NULL AND events.alert_level IS NOT NULL "
                    "AND events.created_at >= NOW() - INTERVAL '24 hours'"
                ).fetchone()["count"]
            else:
                alert_count = db.execute(
                    "SELECT COUNT(*) AS count FROM endpoint_events AS events "
                    "JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                    "WHERE agents.revoked_at IS NULL AND events.alert_level IS NOT NULL "
                    "AND datetime(events.created_at) >= datetime('now', '-1 day')"
                ).fetchone()["count"]
        else:
            agents = db.execute(
                "SELECT id, last_seen_at FROM endpoint_agents WHERE user_id = ? AND revoked_at IS NULL",
                (user["id"],),
            ).fetchall()
            rows = db.execute(
                "SELECT events.id, events.source_ref, events.channel, events.event_time, events.event_id, events.event_name, events.source_ip, events.source_port, "
                "events.destination_ip, events.destination_port, events.network_protocol, events.network_direction, "
                "events.alert_level, events.alert_text, agents.name AS agent_name "
                "FROM endpoint_events AS events JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                "WHERE agents.user_id = ? AND agents.revoked_at IS NULL "
                "ORDER BY events.id DESC LIMIT 20",
                (user["id"],),
            ).fetchall()
            if current_app.config.get("DATABASE_URL"):
                alert_count = db.execute(
                    "SELECT COUNT(*) AS count FROM endpoint_events AS events "
                    "JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                    "WHERE agents.user_id = ? AND agents.revoked_at IS NULL "
                    "AND events.alert_level IS NOT NULL AND events.created_at >= NOW() - INTERVAL '24 hours'",
                    (user["id"],),
                ).fetchone()["count"]
            else:
                alert_count = db.execute(
                    "SELECT COUNT(*) AS count FROM endpoint_events AS events "
                    "JOIN endpoint_agents AS agents ON agents.id = events.agent_id "
                    "WHERE agents.user_id = ? AND agents.revoked_at IS NULL "
                    "AND events.alert_level IS NOT NULL AND datetime(events.created_at) >= datetime('now', '-1 day')",
                    (user["id"],),
                ).fetchone()["count"]

        now = datetime.now(timezone.utc)
        recent = []
        for row in rows:
            item = {
                "event_time": str(row["event_time"]),
                "event_id": row["event_id"],
                "log_source": row["channel"],
                "record_id": str(row["source_ref"]).rsplit(":", 1)[-1],
                "event_name": row["event_name"],
                "source_ip": row["source_ip"] or "Not present",
                "source_port": row["source_port"],
                "destination_ip": row["destination_ip"] or "Not present",
                "destination_port": row["destination_port"],
                "network_protocol": row["network_protocol"] or "",
                "network_direction": row["network_direction"] or "",
                "alert_level": row["alert_level"] or "Event",
                "alert_text": row["alert_text"] or row["event_name"],
                "agent_name": row["agent_name"],
            }
            if user["role"] == "admin":
                item["account_email"] = row["account_email"]
            recent.append(item)
        return jsonify({
            "connected": len(agents),
            "online": sum(_agent_is_online(agent["last_seen_at"], now) for agent in agents),
            "alerts_24h": alert_count,
            "events": recent,
            "refresh_seconds": 15,
        })

    @app.post("/api/agent/events")
    def receive_agent_events():
        if request.content_length and request.content_length > 512 * 1024:
            return jsonify({"error": "Batch is too large."}), 413
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return jsonify({"error": "Agent token required."}), 401
        token = authorization[7:].strip()
        if not token or len(token) > 256:
            return jsonify({"error": "Invalid agent token."}), 401
        db = get_db()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        agent = db.execute(
            "SELECT id, last_seen_at FROM endpoint_agents WHERE token_hash = ? AND revoked_at IS NULL",
            (token_hash,),
        ).fetchone()
        if agent is None:
            return jsonify({"error": "Agent token is invalid or revoked."}), 401
        payload = request.get_json(silent=True)
        events = payload.get("events") if isinstance(payload, dict) else None
        if not isinstance(events, list) or len(events) > 500:
            return jsonify({"error": "Send an events list containing at most 500 records."}), 400

        validated = []
        for item in events:
            if not isinstance(item, dict):
                return jsonify({"error": "Each event must be an object."}), 400
            channel = item.get("channel")
            event_id = item.get("event_id")
            record_id = item.get("record_id")
            if not isinstance(channel, str) or isinstance(event_id, bool) or not isinstance(event_id, int):
                return jsonify({"error": "Event channel or ID is invalid."}), 400
            canonical_channel = {
                "security": "Security",
                "microsoft-windows-windows defender/operational": "Microsoft-Windows-Windows Defender/Operational",
            }.get(channel.strip().casefold())
            rule = WINDOWS_AGENT_EVENT_RULES.get((channel.strip().casefold(), event_id))
            if not canonical_channel or rule is None:
                return jsonify({"error": "This Windows event is not in the accepted event list."}), 400
            if isinstance(record_id, bool) or not str(record_id).isdigit() or len(str(record_id)) > 20:
                return jsonify({"error": "Event record ID is invalid."}), 400
            try:
                event_time = _parse_agent_time(item.get("event_time"))
            except ValueError as error:
                return jsonify({"error": str(error)}), 400
            raw_ip = item.get("source_ip")
            source_ip = None
            if raw_ip not in (None, "", "-"):
                if not isinstance(raw_ip, str) or len(raw_ip) > 64:
                    return jsonify({"error": "Source IP is invalid."}), 400
                try:
                    source_ip = str(ipaddress.ip_address(raw_ip.strip()))
                except ValueError:
                    return jsonify({"error": "Source IP is invalid."}), 400
            destination_ip = None
            raw_destination_ip = item.get("destination_ip")
            if raw_destination_ip not in (None, "", "-"):
                if not isinstance(raw_destination_ip, str) or len(raw_destination_ip) > 64:
                    return jsonify({"error": "Destination IP is invalid."}), 400
                try:
                    destination_ip = str(ipaddress.ip_address(raw_destination_ip.strip()))
                except ValueError:
                    return jsonify({"error": "Destination IP is invalid."}), 400
            ports = {}
            for field in ("source_port", "destination_port"):
                raw_port = item.get(field)
                if raw_port in (None, "", "-"):
                    ports[field] = None
                elif (isinstance(raw_port, bool) or not str(raw_port).isdigit()
                      or not 0 <= int(raw_port) <= 65535):
                    return jsonify({"error": "Network port is invalid."}), 400
                else:
                    ports[field] = int(raw_port)
            raw_protocol = item.get("network_protocol")
            protocol = None
            if raw_protocol not in (None, "", "-"):
                if not isinstance(raw_protocol, str) or not raw_protocol.isdigit() or int(raw_protocol) > 255:
                    return jsonify({"error": "Network protocol is invalid."}), 400
                protocol = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(raw_protocol, f"IP protocol {int(raw_protocol)}")
            raw_direction = item.get("network_direction")
            direction = None
            if raw_direction not in (None, "", "-"):
                if raw_direction not in ("Inbound", "Outbound"):
                    return jsonify({"error": "Network direction is invalid."}), 400
                direction = raw_direction
            event_name, alert_level, alert_text = rule
            validated.append({
                "source_ref": f"{canonical_channel.casefold()}:{record_id}",
                "event_time": event_time.isoformat(timespec="seconds"),
                "channel": canonical_channel,
                "event_id": event_id,
                "source_ip": source_ip,
                "source_port": ports["source_port"],
                "destination_ip": destination_ip,
                "destination_port": ports["destination_port"],
                "network_protocol": protocol,
                "network_direction": direction,
                "event_name": event_name,
                "alert_level": alert_level,
                "alert_text": alert_text,
            })

        accepted = 0
        alerts_created = 0
        for event in validated:
            cursor = db.execute(
                "INSERT INTO endpoint_events "
                "(agent_id, source_ref, event_time, channel, event_id, source_ip, source_port, destination_ip, "
                "destination_port, network_protocol, network_direction, event_name, alert_level, alert_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(agent_id, source_ref) DO NOTHING RETURNING id",
                (agent["id"], event["source_ref"], event["event_time"], event["channel"], event["event_id"],
                 event["source_ip"], event["source_port"], event["destination_ip"], event["destination_port"],
                 event["network_protocol"], event["network_direction"], event["event_name"],
                 event["alert_level"], event["alert_text"]),
            )
            inserted = cursor.fetchone()
            if inserted is None:
                continue
            accepted += 1
            if event["event_id"] == 4625 and event["source_ip"]:
                if current_app.config.get("DATABASE_URL"):
                    failures = db.execute(
                        "SELECT COUNT(*) AS count FROM endpoint_events WHERE agent_id = ? AND event_id = 4625 "
                        "AND source_ip = ? AND created_at >= NOW() - INTERVAL '5 minutes'",
                        (agent["id"], event["source_ip"]),
                    ).fetchone()["count"]
                else:
                    failures = db.execute(
                        "SELECT COUNT(*) AS count FROM endpoint_events WHERE agent_id = ? AND event_id = 4625 "
                        "AND source_ip = ? AND datetime(created_at) >= datetime('now', '-5 minutes')",
                        (agent["id"], event["source_ip"]),
                    ).fetchone()["count"]
                if failures == 5:
                    event["alert_level"] = "High"
                    event["alert_text"] = "Five failed Windows sign-ins from the same IP within five minutes. Verify whether they were expected."
                    db.execute(
                        "UPDATE endpoint_events SET alert_level = ?, alert_text = ? WHERE id = ?",
                        (event["alert_level"], event["alert_text"], inserted["id"]),
                    )
            if event["alert_level"]:
                alerts_created += 1

        db.execute("UPDATE endpoint_agents SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?", (agent["id"],))
        db.commit()
        return jsonify({"accepted": accepted, "alerts_created": alerts_created})

    @app.route("/tools/ip", methods=["GET", "POST"])
    @scan_access
    def scan_ip():
        return run_scan_page(
            module="IP Detection",
            page_title="IP Detection",
            description="Check address type and basic network indicators locally.",
            analyzer=analyze_ip,
        )

    @app.route("/tools/url", methods=["GET", "POST"])
    @scan_access
    def scan_url():
        return run_scan_page(
            module="URL Scanner",
            page_title="URL Scanner",
            description="Review URL structure and limited public website details.",
            analyzer=analyze_url_live,
        )

    @app.route("/tools/file", methods=["GET", "POST"])
    @scan_access
    def analyze_uploaded_file():
        result = None
        rate_limited = False
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            uploaded = request.files.get("file")
            if uploaded is None or not uploaded.filename:
                flash("Choose a file to analyze.", "error")
            elif get_current_user() is None and guest_scans_remaining() == 0:
                rate_limited = True
                flash("You have used all 4 free scans. Sign in or create an account to continue scanning.", "error")
            elif get_current_user() is not None and scan_rate_limited(get_current_user()["id"]):
                rate_limited = True
                flash("Scan limit reached. Please wait until the next minute before scanning again.", "error")
            else:
                content = uploaded.stream.read(5 * 1024 * 1024 + 1)
                if len(content) > 5 * 1024 * 1024:
                    flash("The file is too large. Maximum file size is 5 MB.", "error")
                else:
                    from werkzeug.utils import secure_filename

                    try:
                        result = analyze_file(secure_filename(uploaded.filename), content)
                    except ValueError as error:
                        flash(str(error), "error")
                    else:
                        user = get_current_user()
                        if user is None:
                            record_guest_scan()
                        else:
                            db = get_db()
                            scan_cursor = db.execute(
                                "INSERT INTO scans (user_id, module, target, risk, summary, analysis_details) "
                                "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                                (user["id"], "File Analyzer", result["target"], result["risk"],
                                 result["summary"], json.dumps(persisted_analysis_details(result), ensure_ascii=False)),
                            )
                            db.commit()
                            result["scan_id"] = scan_cursor.fetchone()["id"]

        return render_template("file_analyzer.html", page_title="File Analyzer", result=result), 429 if rate_limited else 200

    @app.route("/tools/logs", methods=["GET", "POST"])
    @scan_access
    def analyze_log_text():
        result = None
        submitted_text = ""
        nessus_content = None
        rate_limited = False
        input_valid = True
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            submitted_text = request.form.get("log_text", "")
            uploaded = request.files.get("log_file")
            has_upload = uploaded is not None and bool(uploaded.filename)
            if has_upload and submitted_text.strip():
                input_valid = False
                flash("Paste logs or upload one log file, not both.", "error")
            elif has_upload:
                from pathlib import Path

                suffix = Path(uploaded.filename).suffix.lower()
                if suffix == ".nessus":
                    nessus_content = uploaded.stream.read(5 * 1024 * 1024 + 1)
                    if len(nessus_content) > 5 * 1024 * 1024:
                        input_valid = False
                        nessus_content = None
                        flash("Nessus report is too large. Maximum size is 5 MB.", "error")
                    elif not nessus_content.strip():
                        input_valid = False
                        nessus_content = None
                        flash("The selected Nessus report is empty.", "error")
                elif suffix not in {".log", ".txt", ".json", ".jsonl", ".csv"}:
                    input_valid = False
                    flash("Choose a .nessus, .log, .txt, .json, .jsonl, or .csv file.", "error")
                else:
                    raw_log = uploaded.stream.read(80001)
                    if len(raw_log) > 80000:
                        input_valid = False
                        flash("Log file is too large. Maximum size is 20,000 text characters.", "error")
                    else:
                        try:
                            submitted_text = raw_log.decode("utf-8-sig")
                            if "\x00" in submitted_text:
                                raise ValueError("This looks like a binary file. Choose a plain-text log file.")
                            if not submitted_text.strip():
                                flash("The selected log file is empty. Choose a file with log lines.", "error")
                                submitted_text = ""
                                input_valid = False
                        except UnicodeDecodeError:
                            input_valid = False
                            flash("Could not read this file as UTF-8 text. Save it as UTF-8 and try again.", "error")
                        except ValueError as error:
                            input_valid = False
                            flash(str(error), "error")
            user = get_current_user()
            scan_submitted = input_valid and (bool(submitted_text.strip()) or nessus_content is not None)
            if scan_submitted and user is None and guest_scans_remaining() == 0:
                rate_limited = True
                submitted_text = ""
                nessus_content = None
                flash("You have used all 4 free scans. Sign in or create an account to continue scanning.", "error")
            elif scan_submitted and user is not None and scan_rate_limited(user["id"]):
                rate_limited = True
                submitted_text = ""
                nessus_content = None
                flash("Scan limit reached. Please wait until the next minute before scanning again.", "error")
            elif scan_submitted:
                try:
                    result = analyze_nessus_report(nessus_content) if nessus_content is not None else analyze_logs(submitted_text)
                except ValueError as error:
                    nessus_content = None
                    flash(str(error), "error")
                else:
                    if user is None:
                        record_guest_scan()
                    else:
                        db = get_db()
                        scan_cursor = db.execute(
                            "INSERT INTO scans (user_id, module, target, risk, summary, analysis_details) "
                            "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                            (user["id"], result.get("module", "Log Analysis"), result["target"], result["risk"],
                             result["summary"], json.dumps(persisted_analysis_details(result), ensure_ascii=False)),
                        )
                        db.commit()
                        result["scan_id"] = scan_cursor.fetchone()["id"]
                    submitted_text = ""

        return render_template(
            "log_analysis.html",
            page_title="Log Analysis",
            result=result,
            submitted_text=submitted_text,
        ), 429 if rate_limited else 200

    @app.get("/alerts-history")
    @login_required
    def alerts_history():
        user = get_current_user()
        if user["role"] == "admin":
            scans = get_db().execute(
                "SELECT scans.id, scans.module, scans.target, scans.risk, scans.summary, scans.created_at, users.email, "
                "scans.user_hidden_at "
                "FROM scans JOIN users ON users.id = scans.user_id ORDER BY scans.id DESC"
            ).fetchall()
        else:
            scans = get_db().execute(
                "SELECT id, module, target, risk, summary, created_at "
                "FROM scans WHERE user_id = ? AND user_hidden_at IS NULL ORDER BY id DESC",
                (user["id"],),
            ).fetchall()
        review_items = [scan for scan in scans if risk_level(scan["risk"]) in {"Low", "Medium", "High", "Critical"}]
        return render_template(
            "alerts_history.html",
            page_title="Alerts & History",
            scans=scans,
            review_items=review_items,
            admin_view=user["role"] == "admin",
        )

    @app.post("/history/clear")
    @login_required
    def clear_user_history():
        if not validate_csrf():
            abort(400)
        user = get_current_user()
        if user["role"] != "user":
            abort(403)

        db = get_db()
        cursor = db.execute(
            "UPDATE scans SET user_hidden_at = CURRENT_TIMESTAMP "
            "WHERE user_id = ? AND user_hidden_at IS NULL",
            (user["id"],),
        )
        db.commit()
        count = cursor.rowcount
        flash(f"Hid {count} scan record(s) from your account history. Admins can still view them.", "success")
        return redirect(url_for("alerts_history"))

    @app.get("/scans/<int:scan_id>")
    @login_required
    def scan_detail(scan_id):
        viewer = get_current_user()
        scan = get_db().execute(
            "SELECT scans.id, scans.user_id, scans.module, scans.target, scans.risk, scans.summary, "
            "scans.created_at, scans.user_hidden_at, scans.analysis_details, users.email "
            "FROM scans JOIN users ON users.id = scans.user_id WHERE scans.id = ?",
            (scan_id,),
        ).fetchone()
        if scan is None or (viewer["role"] != "admin" and (
            scan["user_id"] != viewer["id"] or scan["user_hidden_at"] is not None
        )):
            abort(404)
        details_value = scan["analysis_details"] or "{}"
        try:
            details = json.loads(details_value) if isinstance(details_value, str) else details_value
        except (TypeError, json.JSONDecodeError):
            details = {}
        if isinstance(details, dict):
            details = ensure_saved_log_summaries(details)
        return render_template(
            "scan_detail.html",
            page_title="Scan details",
            scan=scan,
            details=details if isinstance(details, dict) else {},
            admin_view=viewer["role"] == "admin",
        )

    @app.get("/scans/<int:scan_id>/report.pdf")
    @login_required
    def download_scan_pdf(scan_id):
        viewer = get_current_user()
        scan = get_db().execute(
            "SELECT scans.id, scans.user_id, scans.module, scans.target, scans.risk, scans.summary, "
            "scans.created_at, scans.user_hidden_at, scans.analysis_details, users.email "
            "FROM scans JOIN users ON users.id = scans.user_id WHERE scans.id = ?",
            (scan_id,),
        ).fetchone()
        if scan is None or (viewer["role"] != "admin" and (
            scan["user_id"] != viewer["id"] or scan["user_hidden_at"] is not None
        )):
            abort(404)
        details_value = scan["analysis_details"] or "{}"
        try:
            details = json.loads(details_value) if isinstance(details_value, str) else details_value
        except (TypeError, json.JSONDecodeError):
            details = {}
        if not isinstance(details, dict):
            details = {}
        details = ensure_saved_log_summaries(details)
        if viewer["role"] == "admin":
            record_admin_activity("Downloaded scan PDF", f"Scan #{scan_id}", f"Account: {scan['email']}")
        report = build_scan_pdf(scan, details, risk_level(scan["risk"]), ist_datetime(scan["created_at"]))
        return send_file(
            report,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"cybershield-scan-{scan_id}.pdf",
        )

    @app.post("/admin/history/clear-users")
    @admin_required
    def clear_user_scans():
        if not validate_csrf():
            abort(400)
        db = get_db()
        cursor = db.execute(
            "DELETE FROM scans WHERE user_id IN "
            "(SELECT id FROM users WHERE role = 'user')"
        )
        count = cursor.rowcount
        record_admin_activity("Cleared User scans", "All User accounts", f"Deleted {count} scan record(s).", commit=False)
        db.commit()
        flash(f"Cleared {count} scan record(s) from all User accounts.", "success")
        return redirect(url_for("alerts_history"))

    @app.post("/admin/history/clear-admins")
    @admin_required
    def clear_admin_scans():
        if not validate_csrf():
            abort(400)
        db = get_db()
        cursor = db.execute(
            "DELETE FROM scans WHERE user_id IN "
            "(SELECT id FROM users WHERE role = 'admin')"
        )
        count = cursor.rowcount
        record_admin_activity("Cleared Admin scans", "All Admin accounts", f"Deleted {count} scan record(s).", commit=False)
        db.commit()
        flash(f"Cleared {count} scan record(s) from Admin accounts.", "success")
        return redirect(url_for("alerts_history"))

    @app.get("/reports")
    @login_required
    def reports():
        user = get_current_user()
        if user["role"] == "admin":
            scans = get_db().execute(
                "SELECT scans.module, scans.target, scans.risk, scans.summary, scans.created_at, users.email, "
                "scans.user_hidden_at "
                "FROM scans JOIN users ON users.id = scans.user_id ORDER BY scans.id DESC"
            ).fetchall()
        else:
            scans = get_db().execute(
                "SELECT module, target, risk, summary, created_at "
                "FROM scans WHERE user_id = ? AND user_hidden_at IS NULL ORDER BY id DESC",
                (user["id"],),
            ).fetchall()
        module_counts = {}
        for scan in scans:
            module_counts[scan["module"]] = module_counts.get(scan["module"], 0) + 1
        risk_counts = {
            level: sum(risk_level(scan["risk"]) == level for scan in scans)
            for level in ("Info", "Low", "Medium", "High", "Critical")
        }
        return render_template(
            "reports.html",
            page_title="Reports",
            scans=scans,
            module_counts=module_counts,
            risk_counts=risk_counts,
            admin_view=user["role"] == "admin",
        )

    @app.get("/reports/download")
    @login_required
    def download_report():
        user = get_current_user()
        is_admin = user["role"] == "admin"
        if is_admin:
            scans = get_db().execute(
                "SELECT scans.module, scans.target, scans.risk, scans.summary, scans.created_at, users.email, "
                "scans.user_hidden_at "
                "FROM scans JOIN users ON users.id = scans.user_id ORDER BY scans.id DESC"
            ).fetchall()
        else:
            scans = get_db().execute(
                "SELECT module, target, risk, summary, created_at "
                "FROM scans WHERE user_id = ? AND user_hidden_at IS NULL ORDER BY id DESC",
                (user["id"],),
            ).fetchall()

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        headers = (["User"] if is_admin else []) + ["Module", "Target", "Risk", "Summary", "Time (IST)"]
        writer.writerow(headers)
        for scan in scans:
            values = ([scan["email"]] if is_admin else []) + [
                scan["module"], scan["target"], risk_level(scan["risk"]), scan["summary"], ist_datetime(scan["created_at"])
            ]
            writer.writerow([safe_csv_cell(value) for value in values])
        report = io.BytesIO(output.getvalue().encode("utf-8-sig"))
        report.seek(0)
        if is_admin:
            record_admin_activity("Downloaded workspace CSV report", "All accounts", f"Exported {len(scans)} scan record(s).")
        filename = f"cybershield-report-{datetime.now(INDIA_TIMEZONE):%Y%m%d-%H%M%S}.csv"
        return send_file(report, mimetype="text/csv; charset=utf-8", as_attachment=True, download_name=filename)

    @app.route("/admin/users", methods=["GET", "POST"])
    @admin_required
    def manage_users():
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not valid_email(email):
                flash("Enter a valid email address.", "error")
            elif len(password) < 12:
                flash("Temporary password must be at least 12 characters.", "error")
            else:
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user')",
                        (email, generate_password_hash(password)),
                    )
                    record_admin_activity("Created User account", email, commit=False)
                    db.commit()
                except INTEGRITY_ERRORS:
                    get_db().rollback()
                    flash("An account with this email address already exists.", "error")
                else:
                    flash("User account created successfully.", "success")
                    return redirect(url_for("manage_users"))

        users = get_db().execute(
            "SELECT users.id, users.email, users.role, users.created_at, "
            "COUNT(scans.id) AS scan_count FROM users "
            "LEFT JOIN scans ON scans.user_id = users.id "
            "GROUP BY users.id ORDER BY users.id"
        ).fetchall()
        return render_template("manage_users.html", users=users, page_title="Manage users")

    @app.post("/admin/users/reset-password")
    @admin_required
    def reset_user_password():
        if not validate_csrf():
            abort(400)
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not valid_email(email):
            flash("Enter a valid user email address.", "error")
        elif len(password) < 12:
            flash("Temporary password must be at least 12 characters.", "error")
        else:
            db = get_db()
            account = db.execute(
                "SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND role = 'user'", (email,)
            ).fetchone()
            if account is None:
                flash("User account not found.", "error")
            else:
                password_hash = generate_password_hash(password)
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (password_hash, account["id"]),
                )
                record_admin_activity("Reset User password", email, "Temporary password set; no password value was recorded.", commit=False)
                db.commit()
                flash("Temporary password reset. Share it privately and ask the user to change it after signing in.", "success")
        return redirect(url_for("manage_users"))

    @app.get("/health")
    def health():
        return jsonify(status="ok", app="CyberShield"), 200

    @app.get("/robots.txt")
    def robots_txt():
        content = (
            "User-agent: Google-InspectionTool\n"
            "Allow: /\n\n"
            "User-agent: *\n"
            "Allow: /\n"
            "Disallow: /dashboard\n"
            "Disallow: /admin/\n"
            "Disallow: /tools/\n"
            "Disallow: /alerts-history\n"
            "Disallow: /reports\n"
            "Disallow: /scans/\n"
            "Disallow: /account/\n"
            "Disallow: /setup\n"
            "Disallow: /forgot-password\n"
            "Disallow: /reset-password\n"
            "Sitemap: https://cybershield-kb.onrender.com/sitemap.xml\n"
        )
        response = app.response_class(content, mimetype="text/plain")
        # Prevent a CDN from retaining an older robots policy after it changes.
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    @app.get("/sitemap.xml")
    def sitemap_xml():
        content = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://cybershield-kb.onrender.com/</loc></url>'
            '</urlset>'
        )
        return app.response_class(content, mimetype="application/xml")

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="This page could not be found."), 404

    @app.errorhandler(413)
    def request_too_large(_error):
        return render_template("error.html", code=413, message="The upload is too large. Choose a file no larger than 5 MB."), 413

    return app


def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def brevo_is_configured():
    return bool(
        current_app.config.get("BREVO_API_KEY")
        and current_app.config.get("BREVO_SENDER_EMAIL")
    )


def send_password_reset_email(recipient, code):
    if not brevo_is_configured():
        return False
    api_key = current_app.config["BREVO_API_KEY"]
    sender_email = current_app.config["BREVO_SENDER_EMAIL"]
    payload = json.dumps({
        "sender": {"name": "CyberShield", "email": sender_email},
        "to": [{"email": recipient}],
        "subject": "Your CyberShield password reset code",
        "textContent": (
            f"Your CyberShield password reset code is {code}.\n\n"
            "It expires in 10 minutes and can be used only once. If you did not request it, ignore this email."
        ),
    })
    connection = None
    try:
        connection = http.client.HTTPSConnection("api.brevo.com", timeout=15)
        connection.request(
            "POST",
            "/v3/smtp/email",
            body=payload,
            headers={
                "accept": "application/json",
                "api-key": api_key,
                "content-type": "application/json",
            },
        )
        response = connection.getresponse()
        response.read()
        if not 200 <= response.status < 300:
            current_app.logger.error(
                "Brevo password reset delivery failed (HTTP %s).", response.status
            )
            return False
    except (OSError, http.client.HTTPException, ValueError):
        current_app.logger.error("Brevo password reset request failed before acceptance.")
        return False
    finally:
        if connection is not None:
            connection.close()
    return True


def password_reset_code_digest(user_id, code):
    secret = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    payload = f"password-reset:{user_id}:{code}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def parse_utc_datetime(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def load_secret_key(instance_path):
    configured_key = os.getenv("SECRET_KEY")
    if configured_key:
        return configured_key

    key_path = Path(instance_path) / "secret_key"
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()

    key = secrets.token_hex(32)
    key_path.write_text(key, encoding="utf-8")
    return key


def validate_csrf():
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def make_password_token(password_hash):
    key = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(key, password_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def get_current_user():
    if "current_user" not in g:
        user_id = session.get("user_id")
        if user_id is None:
            g.current_user = None
        else:
            account = get_db().execute(
                "SELECT id, email, role, password_hash FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            supplied_token = session.get("password_token", "")
            if account is None or not hmac.compare_digest(
                supplied_token, make_password_token(account["password_hash"])
            ):
                session.clear()
                g.current_user = None
            else:
                g.current_user = {key: account[key] for key in ("id", "email", "role")}
    return g.current_user


def has_users():
    return bool(get_db().execute("SELECT EXISTS(SELECT 1 FROM users) AS has_users").fetchone()["has_users"])


def valid_email(email):
    return len(email) <= 254 and "@" in email and " " not in email


def safe_csv_cell(value):
    """Prevent spreadsheet formulas when exporting user-controlled values."""
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def record_admin_activity(action, target="", details="", commit=True, actor=None):
    """Save an administrator action without recording credentials or secrets."""
    actor = actor or get_current_user()
    if actor is None or actor["role"] != "admin":
        return
    db = get_db()
    db.execute(
        "INSERT INTO admin_activity (actor_email, action, target, details) VALUES (?, ?, ?, ?)",
        (actor["email"], action[:120], str(target)[:300], str(details)[:500]),
    )
    if commit:
        db.commit()


def scan_rate_limited(user_id):
    """Allow five scan submissions per account in each UTC minute window."""
    db = get_db()
    now = datetime.now(timezone.utc)
    window_start = now.replace(second=0, microsecond=0).isoformat(sep=" ", timespec="seconds")
    cursor = db.execute(
        "INSERT INTO scan_rate_limits (user_id, window_start, request_count) VALUES (?, ?, 1) "
        "ON CONFLICT (user_id, window_start) DO UPDATE "
        "SET request_count = scan_rate_limits.request_count + 1 RETURNING request_count",
        (user_id, window_start),
    )
    request_count = cursor.fetchone()["request_count"]
    if current_app.config.get("DATABASE_URL"):
        db.execute("DELETE FROM scan_rate_limits WHERE window_start < NOW() - INTERVAL '1 day'")
    else:
        db.execute("DELETE FROM scan_rate_limits WHERE datetime(window_start) < datetime('now', '-1 day')")
    db.commit()
    return request_count > 5


def guest_scans_remaining():
    """Return the remaining guest scans for this signed browser session."""
    try:
        used = max(0, int(session.get("guest_scans_used", 0)))
    except (TypeError, ValueError):
        used = 0
    return max(0, GUEST_FREE_SCANS - used)


def record_guest_scan():
    """Count a successfully completed, non-persisted guest scan."""
    session["guest_scans_used"] = GUEST_FREE_SCANS - guest_scans_remaining() + 1


def scan_access(view):
    """Allow the scan pages to render for signed-in users and guests."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        return view(*args, **kwargs)
    return wrapped


def ist_datetime(value):
    """Format SQLite or PostgreSQL UTC timestamps as India Standard Time."""
    if not value:
        return ""
    if isinstance(value, str):
        timestamp = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    else:
        timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(INDIA_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")


def run_scan_page(module, page_title, description, analyzer):
    user = get_current_user()
    result = None
    submitted_value = ""
    rate_limited = False

    if request.method == "POST":
        if not validate_csrf():
            abort(400)
        submitted_value = request.form.get("target", "").strip()
        if submitted_value and user is None and guest_scans_remaining() == 0:
            rate_limited = True
            flash("You have used all 4 free scans. Sign in or create an account to continue scanning.", "error")
        elif submitted_value and user is not None and scan_rate_limited(user["id"]):
            rate_limited = True
            flash("Scan limit reached. Please wait until the next minute before scanning again.", "error")
        else:
            try:
                result = analyzer(submitted_value)
            except ValueError as error:
                flash(str(error), "error")
            else:
                if user is None:
                    record_guest_scan()
                else:
                    db = get_db()
                    scan_cursor = db.execute(
                        "INSERT INTO scans (user_id, module, target, risk, summary, analysis_details) "
                        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                        (user["id"], module, result["target"], result["risk"], result["summary"],
                         json.dumps(persisted_analysis_details(result), ensure_ascii=False)),
                    )
                    db.commit()
                    result["scan_id"] = scan_cursor.fetchone()["id"]

    return render_template(
        "scanner.html",
        page_title=page_title,
        module=module,
        description=description,
        result=result,
        submitted_value=submitted_value,
    ), 429 if rate_limited else 200


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            session.clear()
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "1") == "1")
