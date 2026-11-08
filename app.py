"""CyberShield's Flask application entry point."""

from functools import wraps
import csv
import hashlib
import hmac
import http.client
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

from database import INTEGRITY_ERRORS, close_db, get_db, init_db
from detectors import analyze_file, analyze_ip, analyze_logs, analyze_url
from site_inspector import inspect_public_site
from pdf_reports import build_scan_pdf


load_dotenv()
INDIA_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")


def risk_level(value):
    """Normalize current and older stored labels to the four-level display scale."""
    return {
        "informational": "Normal",
        "unverified": "Normal",
        "review": "Low",
        "normal": "Normal",
        "low": "Low",
        "high": "High",
        "critical": "Critical",
    }.get(str(value).lower(), str(value).title())


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

    risk_counts = {label: 0 for label in ("Normal", "Low", "High", "Critical")}
    for row in risk_rows:
        label = risk_level(row["risk"])
        if label not in risk_counts:
            label = "Low"
        risk_counts[label] += row["count"]
    risk_total = sum(risk_counts.values())
    risk_colors = {"Normal": "#34d399", "Low": "#55b8ff", "High": "#ffb84d", "Critical": "#ff5878"}
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

    module_order = ("IP Detection", "URL Scanner", "File Analyzer", "Log Analysis")
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
        if label in {"Low", "High", "Critical"}:
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
        "facts", "line_count", "counts", "event_categories", "file_type", "size", "sha256", "findings", "analysis_scope",
    }
    return {key: value for key, value in result.items() if key in allowed}


def analyze_url_live(value):
    result = analyze_url(value)
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


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=load_secret_key(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "cybershield.sqlite3"),
        DATABASE_URL=os.getenv("DATABASE_URL", "").strip(),
        BREVO_API_KEY=os.getenv("BREVO_API_KEY", "").strip(),
        BREVO_SENDER_EMAIL=os.getenv("BREVO_SENDER_EMAIL", "").strip(),
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
        return {"csrf_token": csrf_token, "current_user": get_current_user()}

    @app.get("/")
    def home():
        if not has_users():
            return redirect(url_for("setup"))
        user = get_current_user()
        if user is None:
            return render_template("home.html")
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

    @app.route("/tools/ip", methods=["GET", "POST"])
    @login_required
    def scan_ip():
        return run_scan_page(
            module="IP Detection",
            page_title="IP Detection",
            description="Check address type and basic network indicators locally.",
            analyzer=analyze_ip,
        )

    @app.route("/tools/url", methods=["GET", "POST"])
    @login_required
    def scan_url():
        return run_scan_page(
            module="URL Scanner",
            page_title="URL Scanner",
            description="Review URL structure and limited public website details.",
            analyzer=analyze_url_live,
        )

    @app.route("/tools/file", methods=["GET", "POST"])
    @login_required
    def analyze_uploaded_file():
        result = None
        rate_limited = False
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            uploaded = request.files.get("file")
            if uploaded is None or not uploaded.filename:
                flash("Choose a file to analyze.", "error")
            elif scan_rate_limited(get_current_user()["id"]):
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
                        db = get_db()
                        scan_cursor = db.execute(
                            "INSERT INTO scans (user_id, module, target, risk, summary, analysis_details) "
                            "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                            (get_current_user()["id"], "File Analyzer", result["target"], result["risk"],
                             result["summary"], json.dumps(persisted_analysis_details(result), ensure_ascii=False)),
                        )
                        db.commit()
                        result["scan_id"] = scan_cursor.fetchone()["id"]

        return render_template("file_analyzer.html", page_title="File Analyzer", result=result), 429 if rate_limited else 200

    @app.route("/tools/logs", methods=["GET", "POST"])
    @login_required
    def analyze_log_text():
        result = None
        submitted_text = ""
        rate_limited = False
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            submitted_text = request.form.get("log_text", "")
            if submitted_text.strip() and scan_rate_limited(get_current_user()["id"]):
                rate_limited = True
                submitted_text = ""
                flash("Scan limit reached. Please wait until the next minute before scanning again.", "error")
            else:
                try:
                    result = analyze_logs(submitted_text)
                except ValueError as error:
                    flash(str(error), "error")
                else:
                    db = get_db()
                    scan_cursor = db.execute(
                        "INSERT INTO scans (user_id, module, target, risk, summary, analysis_details) "
                        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                        (get_current_user()["id"], "Log Analysis", result["target"], result["risk"],
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
        review_items = [scan for scan in scans if risk_level(scan["risk"]) in {"Low", "High", "Critical"}]
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
            for level in ("Normal", "Low", "High", "Critical")
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
        return app.response_class(content, mimetype="text/plain")

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
        if submitted_value and scan_rate_limited(user["id"]):
            rate_limited = True
            flash("Scan limit reached. Please wait until the next minute before scanning again.", "error")
        else:
            try:
                result = analyzer(submitted_value)
            except ValueError as error:
                flash(str(error), "error")
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
