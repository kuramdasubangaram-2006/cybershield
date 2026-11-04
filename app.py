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


def persisted_analysis_details(result):
    """Keep derived findings only; never persist uploaded bytes or pasted log text."""
    allowed = {
        "label", "explanation", "site_explanation", "redirect_chain", "indicators", "recommendations",
        "facts", "line_count", "counts", "file_type", "size", "sha256",
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
            return redirect(url_for("login"))
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
                session.permanent = "remember" in request.form
                return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.post("/logout")
    def logout():
        if not validate_csrf():
            abort(400)
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
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            uploaded = request.files.get("file")
            if uploaded is None or not uploaded.filename:
                flash("Choose a file to analyze.", "error")
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

        return render_template("file_analyzer.html", page_title="File Analyzer", result=result)

    @app.route("/tools/logs", methods=["GET", "POST"])
    @login_required
    def analyze_log_text():
        result = None
        submitted_text = ""
        if request.method == "POST":
            if not validate_csrf():
                abort(400)
            submitted_text = request.form.get("log_text", "")
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
        )

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
        db.commit()
        count = cursor.rowcount
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
        db.commit()
        count = cursor.rowcount
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
                db.commit()
                flash("Temporary password reset. Share it privately and ask the user to change it after signing in.", "success")
        return redirect(url_for("manage_users"))

    @app.get("/health")
    def health():
        return jsonify(status="ok", app="CyberShield"), 200

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

    if request.method == "POST":
        if not validate_csrf():
            abort(400)
        submitted_value = request.form.get("target", "").strip()
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
    )


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
