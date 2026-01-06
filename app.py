import os
import secrets
from datetime import timedelta, datetime

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
)
from flask_session import Session
from flask_session.sessions import FileSystemSessionInterface
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
import json

from init_database import (
    create_connection_pool,
    get_db_connection,
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
    calculate_cumulative_values,
)

from xhtml2pdf import pisa
from io import BytesIO

from functools import wraps


# ---------------------------------------------------------------------------
# Custom Session Interface (Workaround for Python 3.14 compatibility)
# ---------------------------------------------------------------------------

class FixedFileSystemSessionInterface(FileSystemSessionInterface):
    """
    Custom session interface that ensures session_id is always a string.
    This fixes the TypeError with Werkzeug 3.x and Python 3.14.
    """
    def save_session(self, app, session, response):
        """Override save_session to ensure session_id is always a string."""
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        
        if not session:
            if session.modified:
                self.cache.delete(self.key_prefix + session.sid)
                response.delete_cookie(app.config["SESSION_COOKIE_NAME"],
                                       domain=domain, path=path)
            return

        conditional_cookie_kwargs = {}
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        if self.has_same_site_capability:
            conditional_cookie_kwargs["samesite"] = self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)
        data = dict(session)
        
        # Calculate total seconds for cache expiration
        if app.permanent_session_lifetime:
            total_seconds_val = int(app.permanent_session_lifetime.total_seconds())
        else:
            total_seconds_val = int(timedelta(minutes=30).total_seconds())
        
        self.cache.set(self.key_prefix + session.sid, data, total_seconds_val)
        
        # Get session_id and ensure it's a string (not bytes)
        if self.use_signer:
            from itsdangerous import want_bytes
            signed = self._get_signer(app).sign(want_bytes(session.sid))
            # Convert bytes to string if needed
            if isinstance(signed, bytes):
                session_id = signed.decode('utf-8')
            else:
                session_id = str(signed)
        else:
            session_id = str(session.sid)
        
        # Ensure session_id is string before passing to set_cookie
        response.set_cookie(
            app.config["SESSION_COOKIE_NAME"], 
            str(session_id),  # Explicitly convert to string
            expires=expires, 
            httponly=httponly,
            domain=domain, 
            path=path, 
            secure=secure,
            **conditional_cookie_kwargs
        )


# ---------------------------------------------------------------------------
# Flask Application Initialization & Environment Setup
# ---------------------------------------------------------------------------

# Ensure environment variables from HSE/.env are loaded
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_FILE_DIR"] = os.path.join(
    os.path.dirname(__file__), "flask_session_cache"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_NAME"] = "hse_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)

# Use custom session interface to fix Python 3.14 compatibility
app.session_interface = FixedFileSystemSessionInterface(
    cache_dir=app.config["SESSION_FILE_DIR"],
    threshold=500,  # Default threshold
    mode=384,  # Default mode (0o600 in octal)
    key_prefix=app.config.get("SESSION_KEY_PREFIX", "session:"),
    use_signer=app.config.get("SESSION_USE_SIGNER", True),
    permanent=app.config.get("SESSION_PERMANENT", False)
)

# Initialize connection pool at import time for non-__main__ use (e.g. WSGI)
create_connection_pool(pool_size=10)


# ---------------------------------------------------------------------------
# MySQL Database Helper Functions
# ---------------------------------------------------------------------------


def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    """
    Helper to execute parameterized queries using the global connection pool.

    NOTE: This helper will re-raise mysql.connector.Error so that callers can
    decide how to present errors (e.g. JSON vs HTML). Callers must wrap usages
    in try/except and return an appropriate response instead of letting the
    exception bubble up as a generic 500.
    """
    params = params or ()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params)

            result = None
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()

            if commit:
                conn.commit()

            cursor.close()
            return result
    except mysql.connector.Error as e:
        print(f"MySQL error: {e}")
        raise


def is_logged_in() -> bool:
    return bool(session.get("user_id"))


def start_user_session(user: dict) -> None:
    """
    Initialize an authenticated session for the given user.
    """
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["designation"] = user.get("designation")
    session["profile_pic"] = user.get("profile_pic")
    session.permanent = user.get("remember", False)


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        user = execute_query(
            """
            SELECT id, username, email, role, full_name, designation, profile_pic
            FROM users
            WHERE id = %s
            """,
            (user_id,),
            fetch_one=True,
        )
        return user
    except mysql.connector.Error:
        return None


# ---------------------------------------------------------------------------
# Notification Management (JSON-backed)
# ---------------------------------------------------------------------------


NOTIFICATIONS_FILE = os.path.join(os.path.dirname(__file__), "notifications.json")


def _load_notifications():
    """
    Load notifications from the JSON file. Returns a list of notification dicts.
    """
    if not os.path.exists(NOTIFICATIONS_FILE):
        return []
    try:
        with open(NOTIFICATIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_notifications(items):
    """
    Persist the given list of notifications back to the JSON file.
    """
    try:
        with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"Failed to save notifications.json: {e}")


def _prune_notifications(hours: int = 48):
    """
    Remove notifications older than the specified number of hours.
    """
    items = _load_notifications()
    if not items:
        return []

    cutoff = datetime.utcnow().timestamp() - hours * 3600
    pruned = []
    for n in items:
        try:
            created_ts = n.get("created_at")
            if isinstance(created_ts, (int, float)):
                ts = created_ts
            else:
                # If stored as ISO string, try to parse
                ts = datetime.fromisoformat(created_ts).timestamp()
            if ts >= cutoff:
                pruned.append(n)
        except Exception:
            # If parsing fails, keep the notification to avoid accidental loss
            pruned.append(n)

    if len(pruned) != len(items):
        _save_notifications(pruned)
    return pruned


def add_notification(user_id: int, message: str, report_id: int, notification_type: str):
    """
    Append a new notification entry for the given user/report.
    Structure:
    {
        "id": int,
        "user_id": int,
        "message": str,
        "report_id": int,
        "type": str,
        "created_at": float (UTC timestamp),
        "read": bool
    }
    """
    items = _prune_notifications()
    now_ts = datetime.utcnow().timestamp()

    next_id = 1
    if items:
        try:
            next_id = max(int(n.get("id", 0)) for n in items) + 1
        except ValueError:
            next_id = 1

    notification = {
        "id": next_id,
        "user_id": int(user_id) if user_id is not None else None,
        "message": message,
        "report_id": report_id,
        "type": notification_type,
        "created_at": now_ts,
        "read": False,
    }
    items.append(notification)
    _save_notifications(items)
    return notification


# ---------------------------------------------------------------------------
# Authentication Decorators, CSRF Helpers & Session Management
# ---------------------------------------------------------------------------


def require_role(*allowed_roles):
    """
    API-oriented role decorator.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("user_id"):
                return jsonify({"error": "Authentication required"}), 401
            if session.get("role") not in allowed_roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_role_page(*allowed_roles):
    """
    Page-oriented role decorator.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                return redirect(url_for("login"))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_admin(f):
    return require_role("admin")(f)


def require_safety_officer(f):
    return require_role("safety_officer")(f)


def require_project_manager(f):
    return require_role("project_manager")(f)


def require_admin_page(f):
    return require_role_page("admin")(f)


def require_safety_officer_page(f):
    return require_role_page("safety_officer")(f)


def require_project_manager_page(f):
    return require_role_page("project_manager")(f)


def get_or_set_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def verify_csrf_header() -> bool:
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token")
    if not expected or not provided:
        return False
    return secrets.compare_digest(expected, provided)


@app.teardown_appcontext
def teardown_db(exception=None):
    # Connection pool handles cleanup.
    pass


@app.route("/api/hse/notifications", methods=["GET"])
@require_role("safety_officer", "project_manager")
def get_notifications():
    """
    Retrieve notifications for the current (or specified) user.
    Returns:
    {
        "notifications": [...],
        "count": int,
        "unread_count": int
    }
    """
    # Default to current user; optional override via query param
    current_user_id = session.get("user_id")
    user_id_param = request.args.get("user_id")
    try:
        target_user_id = int(user_id_param) if user_id_param else int(current_user_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid user_id parameter"}), 400

    items = _prune_notifications()
    user_items = [n for n in items if n.get("user_id") == target_user_id]

    # Sort newest first
    user_items.sort(key=lambda n: n.get("created_at", 0), reverse=True)

    unread_count = sum(1 for n in user_items if not n.get("read"))

    return jsonify(
        {
            "notifications": user_items,
            "count": len(user_items),
            "unread_count": unread_count,
        }
    )


@app.route("/api/hse/notifications/mark_read", methods=["POST"])
@require_role("safety_officer")
def mark_notifications_read():
    if not verify_csrf_header():
        return jsonify({"success": False, "message": "Invalid CSRF"}), 400

    data = request.get_json(silent=True) or {}
    target_user_id = session.get("user_id")
    items = _load_notifications()
    updated = False

    if data.get("all"):
        for n in items:
            if n.get("user_id") == target_user_id:
                n["read"] = True
                updated = True
    else:
        ids = data.get("ids", [])
        for n in items:
            if n.get("id") in ids and n.get("user_id") == target_user_id:
                n["read"] = True
                updated = True

    if updated:
        _save_notifications(items)

    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Login, Logout & Session Status Routes
# ---------------------------------------------------------------------------


@app.route("/api/auth/csrf-token", methods=["GET"])
def csrf_token():
    token = get_or_set_csrf_token()
    return jsonify({"csrf_token": token})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if is_logged_in():
            role = session.get("role")
            if role == "admin":
                return redirect(url_for("admin_dashboard"))
            elif role == "safety_officer":
                return redirect(url_for("safety_officer_dashboard"))
            elif role == "project_manager":
                return redirect(url_for("project_manager_dashboard"))

        get_or_set_csrf_token()
        return render_template("login.html")

    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )

    if request.is_json:
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip()
        password = data.get("password", "")
        remember = data.get("remember", False)
    else:
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

    if not email or not password:
        return (
            jsonify({"success": False, "message": "Email and password are required"}),
            400,
        )

    try:
        user = execute_query(
            """
            SELECT id, username, email, password_hash, role,
                   full_name, designation, profile_pic
            FROM users
            WHERE email = %s
            """,
            (email,),
            fetch_one=True,
        )
    except mysql.connector.Error:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Database error while verifying credentials",
                }
            ),
            500,
        )

    if not user or not check_password_hash(user["password_hash"], password):
        return (
            jsonify({"success": False, "message": "Invalid credentials"}),
            401,
        )

    # Inject remember flag into user dict for session handling
    user["remember"] = remember
    start_user_session(user)

    redirect_map = {
        "admin": "/admin/dashboard",
        "safety_officer": "/safety_officer/dashboard",
        "project_manager": "/project_manager/dashboard",
    }
    redirect_url = redirect_map.get(user["role"], "/")

    return jsonify({"success": True, "redirect": redirect_url})


@app.route("/logout", methods=["POST"])
def logout():
    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )

    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    if not is_logged_in():
        return jsonify({"logged_in": False})

    user = get_current_user()
    if not user:
        return jsonify({"logged_in": False})

    return jsonify(
        {
            "logged_in": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "full_name": user["full_name"],
                "email": user["email"],
            },
        }
    )


@app.route("/api/auth/check_role", methods=["POST"])
def check_role():
    if not request.is_json:
        return (
            jsonify({"authorized": False, "message": "JSON body required"}),
            400,
        )
    data = request.get_json(silent=True) or {}
    required_role = data.get("required_role")
    if not required_role:
        return (
            jsonify({"authorized": False, "message": "required_role is required"}),
            400,
        )

    if not is_logged_in():
        return jsonify({"authorized": False}), 401

    return jsonify({"authorized": session.get("role") == required_role})


# ---------------------------------------------------------------------------
# Root & Dashboard Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    if not is_logged_in():
        return render_template("landing.html")

    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "safety_officer":
        return redirect(url_for("safety_officer_dashboard"))
    elif role == "project_manager":
        return redirect(url_for("project_manager_dashboard"))

    return redirect(url_for("login"))


@app.route("/admin/dashboard")
@require_admin_page
def admin_dashboard():
    user = get_current_user()
    stats = {
        "total_users": 0,
        "safety_officers": 0,
        "project_managers": 0,
        "total_reports": 0,
        "pending_reports": 0,
        "approved_reports": 0,
    }
    try:
        total_users = execute_query(
            "SELECT COUNT(*) AS count FROM users", fetch_one=True
        )
        safety_officers = execute_query(
            "SELECT COUNT(*) AS count FROM users WHERE role = %s",
            ("safety_officer",),
            fetch_one=True,
        )
        project_managers = execute_query(
            "SELECT COUNT(*) AS count FROM users WHERE role = %s",
            ("project_manager",),
            fetch_one=True,
        )
        total_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports", fetch_one=True
        )
        pending_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports WHERE status = %s",
            ("pending",),
            fetch_one=True,
        )
        approved_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports WHERE status = %s",
            ("approved",),
            fetch_one=True,
        )

        stats = {
            "total_users": total_users["count"] if total_users else 0,
            "safety_officers": safety_officers["count"] if safety_officers else 0,
            "project_managers": project_managers["count"] if project_managers else 0,
            "total_reports": total_reports["count"] if total_reports else 0,
            "pending_reports": pending_reports["count"] if pending_reports else 0,
            "approved_reports": approved_reports["count"] if approved_reports else 0,
        }
    except mysql.connector.Error:
        pass

    return render_template("admin_dashboard.html", user=user, stats=stats)


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    try:
        total_users = execute_query(
            "SELECT COUNT(*) AS count FROM users", fetch_one=True
        )
        safety_officers = execute_query(
            "SELECT COUNT(*) AS count FROM users WHERE role = %s",
            ("safety_officer",),
            fetch_one=True,
        )
        project_managers = execute_query(
            "SELECT COUNT(*) AS count FROM users WHERE role = %s",
            ("project_manager",),
            fetch_one=True,
        )
        total_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports", fetch_one=True
        )
        pending_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports WHERE status = %s",
            ("pending",),
            fetch_one=True,
        )
        approved_reports = execute_query(
            "SELECT COUNT(*) AS count FROM hse_reports WHERE status = %s",
            ("approved",),
            fetch_one=True,
        )

        return jsonify(
            {
                "total_users": total_users["count"] if total_users else 0,
                "safety_officers": safety_officers["count"] if safety_officers else 0,
                "project_managers": project_managers["count"]
                if project_managers
                else 0,
                "total_reports": total_reports["count"] if total_reports else 0,
                "pending_reports": pending_reports["count"]
                if pending_reports
                else 0,
                "approved_reports": approved_reports["count"]
                if approved_reports
                else 0,
            }
        )
    except mysql.connector.Error as e:
        print(f"Error fetching admin stats: {e}")
        return (
            jsonify(
                {
                    "error": "Failed to fetch statistics",
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Admin Configuration Management
# ---------------------------------------------------------------------------


@app.route("/admin/config", methods=["GET"])
@require_admin_page
def admin_config_page():
    user = get_current_user()
    return render_template("admin_config.html", user=user)


def _normalize_config_row(row):
    base = {
        "id": row["id"],
        "config_key": row["config_key"],
        "config_type": row["config_type"],
    }
    if row["config_type"] in ("prepared_by", "approved_by"):
        try:
            value = json.loads(row["config_value"] or "{}")
        except (json.JSONDecodeError, TypeError):
            value = {}
        base.update(
            {
                "name": value.get("name", ""),
                "designation": value.get("designation", ""),
            }
        )
    elif row["config_type"] == "name_of_work":
        base.update({"work_name": row["config_value"]})
    elif row["config_type"] == "contractor":
        base.update({"contractor_name": row["config_value"]})
    elif row["config_type"] == "project":
        try:
            value = json.loads(row["config_value"] or "{}")
        except (json.JSONDecodeError, TypeError):
            value = {}
        base.update(
            {
                "project_code": value.get("code", ""),
                "project_name": value.get("name", ""),
            }
        )
    else:
        base.update({"value": row["config_value"]})
    return base


@app.route("/api/admin/config/<config_type>", methods=["GET"])
@require_admin
def get_admin_configs(config_type):
    if config_type not in ("prepared_by", "approved_by", "contractor", "name_of_work", "project"):
        return (
            jsonify({"error": "Invalid config type"}),
            400,
        )

    try:
        rows = execute_query(
            """
            SELECT id, config_key, config_value, config_type
            FROM admin_config
            WHERE config_type = %s
            ORDER BY id
            """,
            (config_type,),
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching admin_config rows: {e}")
        return (
            jsonify({"error": "Failed to fetch configurations"}),
            500,
        )

    configs = [_normalize_config_row(row) for row in (rows or [])]
    return jsonify(configs)


@app.route("/api/admin/config/add", methods=["POST"])
@require_admin
def add_admin_config():
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    config_type = (data.get("config_type") or "").strip()

    if config_type not in ("prepared_by", "approved_by", "contractor", "name_of_work", "project"):
        return jsonify({"success": False, "message": "Invalid config_type"}), 400

    name = (data.get("name") or "").strip()
    designation = (data.get("designation") or "").strip()
    contractor_name = (data.get("contractor_name") or "").strip()
    work_name = (data.get("work_name") or "").strip()
    project_code = (data.get("project_code") or "").strip()
    project_name = (data.get("project_name") or "").strip()

    if config_type in ("prepared_by", "approved_by"):
        if not name or not designation:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Name and designation are required",
                    }
                ),
                400,
            )
        config_value = json.dumps({"name": name, "designation": designation})
    elif config_type == "contractor":
        if not contractor_name:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Contractor name is required",
                    }
                ),
                400,
            )
        config_value = contractor_name
    elif config_type == "name_of_work":
        if not work_name:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Name of work is required",
                    }
                ),
                400,
            )
        config_value = work_name
    elif config_type == "project":
        if not project_code or not project_name:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Project code and name are required",
                    }
                ),
                400,
            )
        config_value = json.dumps({"code": project_code, "name": project_name})

    try:
        row = execute_query(
            "SELECT MAX(id) AS max_id FROM admin_config",
            fetch_one=True,
        )
        next_id = (row["max_id"] or 0) + 1
        if config_type in ("prepared_by", "approved_by"):
            config_key = f"{config_type}_{next_id}"
            description = (
                "Prepared by profile"
                if config_type == "prepared_by"
                else "Approved by profile"
            )
        elif config_type == "contractor":
            config_key = f"contractor_{next_id}"
            description = "Contractor name"
        elif config_type == "name_of_work":
            config_key = f"name_of_work_{next_id}"
            description = "Name of work for HSE form dropdown"
        elif config_type == "project":
            config_key = f"project_{next_id}"
            description = "Project code and name for HSE form dropdown"

        execute_query(
            """
            INSERT INTO admin_config (config_key, config_value, config_type, description)
            VALUES (%s, %s, %s, %s)
            """,
            (config_key, config_value, config_type, description),
            commit=True,
        )
        return jsonify({"success": True, "message": "Added successfully"})
    except mysql.connector.Error as e:
        print(f"Error adding admin_config row: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to add configuration",
                }
            ),
            500,
        )


@app.route("/api/admin/config/update/<int:config_id>", methods=["POST"])
@require_admin
def update_admin_config(config_id):
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}

    try:
        existing = execute_query(
            """
            SELECT id, config_type, config_value
            FROM admin_config
            WHERE id = %s
            """,
            (config_id,),
            fetch_one=True,
        )
        if not existing:
            return (
                jsonify({"success": False, "message": "Configuration not found"}),
                404,
            )

        config_type = existing["config_type"]
        if config_type in ("prepared_by", "approved_by"):
            name = (data.get("name") or "").strip()
            designation = (data.get("designation") or "").strip()
            if not name or not designation:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Name and designation are required",
                        }
                    ),
                    400,
                )
            new_value = json.dumps({"name": name, "designation": designation})
        elif config_type == "contractor":
            contractor_name = (data.get("contractor_name") or "").strip()
            if not contractor_name:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Contractor name is required",
                        }
                    ),
                    400,
                )
            new_value = contractor_name
        elif config_type == "name_of_work":
            work_name = (data.get("work_name") or "").strip()
            if not work_name:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Name of work is required",
                        }
                    ),
                    400,
                )
            new_value = work_name
        elif config_type == "project":
            project_code = (data.get("project_code") or "").strip()
            project_name = (data.get("project_name") or "").strip()
            if not project_code or not project_name:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Project code and name are required",
                        }
                    ),
                    400,
                )
            new_value = json.dumps({"code": project_code, "name": project_name})
        else:
            return (
                jsonify({"success": False, "message": "Unsupported config type"}),
                400,
            )

        execute_query(
            "UPDATE admin_config SET config_value = %s WHERE id = %s",
            (new_value, config_id),
            commit=True,
        )
        return jsonify({"success": True, "message": "Updated successfully"})
    except mysql.connector.Error as e:
        print(f"Error updating admin_config row: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to update configuration",
                }
            ),
            500,
        )


@app.route("/api/admin/config/delete/<int:config_id>", methods=["DELETE"])
@require_admin
def delete_admin_config(config_id):
    try:
        config = execute_query(
            """
            SELECT id, config_type, config_value
            FROM admin_config
            WHERE id = %s
            """,
            (config_id,),
            fetch_one=True,
        )
        if not config:
            return (
                jsonify({"success": False, "message": "Configuration not found"}),
                404,
            )

        # For certain config types, prevent deletion if they are in use by reports
        if config["config_type"] == "contractor":
            ref = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE contractor_name = %s
                """,
                (config["config_value"],),
                fetch_one=True,
            )
            if ref and ref["count"] > 0:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Cannot delete: contractor is in use by reports",
                        }
                    ),
                    400,
                )
        elif config["config_type"] == "project":
            # Extract project code from JSON
            try:
                project_data = json.loads(config["config_value"] or "{}")
                project_code = project_data.get("code", "")
            except (json.JSONDecodeError, TypeError):
                project_code = ""

            if project_code:
                # Check if project_code column exists in hse_reports before querying
                col_check = execute_query(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'hse_reports'
                      AND COLUMN_NAME = 'project_code'
                    """,
                    fetch_one=True,
                )
                if col_check and col_check["cnt"] > 0:
                    ref = execute_query(
                        """
                        SELECT COUNT(*) AS count
                        FROM hse_reports
                        WHERE project_code = %s
                        """,
                        (project_code,),
                        fetch_one=True,
                    )
                    if ref and ref["count"] > 0:
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "message": "Cannot delete: project code is in use by reports",
                                }
                            ),
                            400,
                        )
        elif config["config_type"] == "name_of_work":
            ref = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE name_of_work = %s
                """,
                (config["config_value"],),
                fetch_one=True,
            )
            if ref and ref["count"] > 0:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Cannot delete: name of work is in use by reports",
                        }
                    ),
                    400,
                )
        # prepared_by and approved_by configs are just dropdown options,
        # and are not directly linked to reports via foreign keys, so we allow deletion

        execute_query(
            "DELETE FROM admin_config WHERE id = %s",
            (config_id,),
            commit=True,
        )
        return jsonify({"success": True, "message": "Deleted successfully"})
    except mysql.connector.Error as e:
        print(f"Error deleting admin_config row: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to delete configuration",
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Admin User Management
# ---------------------------------------------------------------------------


@app.route("/admin/users", methods=["GET"])
@require_admin_page
def admin_users_page():
    user = get_current_user()
    return render_template("admin_users.html", user=user)


def _normalize_email(value: str) -> str:
    return (value or "").strip().lower()


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def get_admin_users():
    try:
        users = execute_query(
            """
            SELECT id, username, email, role, full_name, designation, created_at
            FROM users
            WHERE role IN ('safety_officer', 'project_manager')
            ORDER BY created_at DESC
            """,
            fetch_all=True,
        )
        return jsonify(users or [])
    except mysql.connector.Error as e:
        print(f"Error fetching users: {e}")
        return (
            jsonify({"error": "Failed to fetch users"}),
            500,
        )


@app.route("/api/admin/users/add", methods=["POST"])
@require_admin
def add_admin_user():
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = _normalize_email(data.get("email"))
    password = data.get("password") or ""
    role = (data.get("role") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    designation = (data.get("designation") or "").strip() or None

    if not username or not email or not password or not role or not full_name:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "username, email, password, role, and full_name are required",
                }
            ),
            400,
        )

    if role not in ("safety_officer", "project_manager"):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid role",
                }
            ),
            400,
        )

    try:
        existing = execute_query(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (username, email),
            fetch_one=True,
        )
        if existing:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Username or email already exists",
                    }
                ),
                400,
            )

        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        execute_query(
            """
            INSERT INTO users (username, email, password_hash, role, full_name, designation)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (username, email, password_hash, role, full_name, designation),
            commit=True,
        )
        return jsonify({"success": True, "message": "User created successfully"})
    except mysql.connector.Error as e:
        print(f"Error creating user: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to create user",
                }
            ),
            500,
        )


@app.route("/api/admin/users/update/<int:user_id>", methods=["POST"])
@require_admin
def update_admin_user(user_id):
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = _normalize_email(data.get("email"))
    password = data.get("password") or ""
    role = (data.get("role") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    designation = (data.get("designation") or "").strip() or None

    if not username or not email or not role or not full_name:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "username, email, role, and full_name are required",
                }
            ),
            400,
        )

    if role not in ("safety_officer", "project_manager"):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid role",
                }
            ),
            400,
        )

    try:
        existing = execute_query(
            "SELECT id, role FROM users WHERE id = %s",
            (user_id,),
            fetch_one=True,
        )
        if not existing:
            return (
                jsonify({"success": False, "message": "User not found"}),
                404,
            )

        if existing["role"] == "admin":
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Admin users cannot be modified via this endpoint",
                    }
                ),
                400,
            )

        conflict = execute_query(
            "SELECT id FROM users WHERE (username = %s OR email = %s) AND id != %s",
            (username, email, user_id),
            fetch_one=True,
        )
        if conflict:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Username or email already in use",
                    }
                ),
                400,
            )

        if password:
            password_hash = generate_password_hash(password, method="pbkdf2:sha256")
            execute_query(
                """
                UPDATE users
                SET username = %s,
                    email = %s,
                    role = %s,
                    full_name = %s,
                    designation = %s,
                    password_hash = %s
                WHERE id = %s
                """,
                (username, email, role, full_name, designation, password_hash, user_id),
                commit=True,
            )
        else:
            execute_query(
                """
                UPDATE users
                SET username = %s,
                    email = %s,
                    role = %s,
                    full_name = %s,
                    designation = %s
                WHERE id = %s
                """,
                (username, email, role, full_name, designation, user_id),
                commit=True,
            )

        return jsonify({"success": True, "message": "User updated successfully"})
    except mysql.connector.Error as e:
        print(f"Error updating user: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to update user",
                }
            ),
            500,
        )


@app.route("/api/admin/users/delete/<int:user_id>", methods=["DELETE"])
@require_admin
def delete_admin_user(user_id):
    try:
        user = execute_query(
            "SELECT id, role FROM users WHERE id = %s",
            (user_id,),
            fetch_one=True,
        )
        if not user:
            return (
                jsonify({"success": False, "message": "User not found"}),
                404,
            )

        if user["role"] == "admin":
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Admin users cannot be deleted via this endpoint",
                    }
                ),
                400,
            )

        ref = execute_query(
            """
            SELECT COUNT(*) AS count
            FROM hse_reports
            WHERE prepared_by_id = %s OR approved_by_id = %s
            """,
            (user_id, user_id),
            fetch_one=True,
        )
        if ref and ref["count"] > 0:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Cannot delete: user has associated reports",
                    }
                ),
                400,
            )

        execute_query(
            "DELETE FROM users WHERE id = %s",
            (user_id,),
            commit=True,
        )
        return jsonify({"success": True, "message": "User deleted successfully"})
    except mysql.connector.Error as e:
        print(f"Error deleting user: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Failed to delete user",
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# HSE APIs for Safety Officer Form & Dashboard
# ---------------------------------------------------------------------------


def _normalize_month_name(month_value: str):
    """
    Normalize various month formats to a full month name (e.g. 'January').

    Accepted inputs:
    - Full month name (e.g. 'January', case-insensitive)
    - Numeric month (e.g. '1' or '01')
    - Canonical 'YYYY-MM' (e.g. '2025-01')
    """
    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }

    value = (month_value or "").strip()
    if not value:
        return None

    month_num = None

    # Canonical 'YYYY-MM'
    if (
        len(value) == 7
        and value[4] == "-"
        and value[:4].isdigit()
        and value[5:].isdigit()
    ):
        month_num = int(value[5:])
    # Plain numeric month 'MM' or 'M'
    elif value.isdigit():
        num = int(value)
        if 1 <= num <= 12:
            month_num = num
    else:
        month_num = month_map.get(value.lower())

    if not month_num or not (1 <= month_num <= 12):
        return None

    reverse_map = {v: k for k, v in month_map.items()}
    return reverse_map[month_num].capitalize()


def _get_previous_month(month_value: str, year: int):
    """
    Given a month value and a year, return the previous month (as full
    month name) and the corresponding year.

    `month_value` can be:
    - Full month name (e.g. 'January')
    - Numeric month (e.g. '1' or '01')
    - Canonical 'YYYY-MM' (e.g. '2025-01')
    """
    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }

    value = (month_value or "").strip()
    if not value:
        return None, None

    month_num = None
    current_year = year

    # Canonical 'YYYY-MM'
    if (
        len(value) == 7
        and value[4] == "-"
        and value[:4].isdigit()
        and value[5:].isdigit()
    ):
        current_year = int(value[:4])
        month_num = int(value[5:])
    # Plain numeric month 'MM' or 'M'
    elif value.isdigit():
        num = int(value)
        if 1 <= num <= 12:
            month_num = num
    else:
        month_num = month_map.get(value.lower())

    if not month_num or not (1 <= month_num <= 12):
        return None, None

    if month_num == 1:
        prev_month_num = 12
        prev_year = current_year - 1
    else:
        prev_month_num = month_num - 1
        prev_year = current_year

    reverse_map = {v: k for k, v in month_map.items()}
    prev_month_name = reverse_map[prev_month_num].capitalize()
    return prev_month_name, prev_year


def _check_unapproved_reports_before(month: str, year: int, project_code: str, exclude_report_id: int = None):
    """
    Check if there are any unapproved reports (pending or rejected) 
    before the given month/year for a specific project. Returns True if unapproved reports exist.
    
    This ensures cumulative calculations are accurate by preventing
    new reports when previous reports haven't been approved yet.
    
    Args:
        month: Full month name (e.g. 'January')
        year: Year (integer)
        project_code: Project code to filter by
        exclude_report_id: Optional report ID to exclude from the check (useful for updates)
    """
    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }
    
    month_num = month_map.get(month.lower())
    if not month_num:
        return False
    
    try:
        # Check for any reports before this month/year that are not approved for this project
        # We need to check all months/years before the current one
        if exclude_report_id:
            unapproved = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE (
                    (year < %s) OR
                    (year = %s AND (
                        CASE LOWER(month)
                            WHEN 'january' THEN 1
                            WHEN 'february' THEN 2
                            WHEN 'march' THEN 3
                            WHEN 'april' THEN 4
                            WHEN 'may' THEN 5
                            WHEN 'june' THEN 6
                            WHEN 'july' THEN 7
                            WHEN 'august' THEN 8
                            WHEN 'september' THEN 9
                            WHEN 'october' THEN 10
                            WHEN 'november' THEN 11
                            WHEN 'december' THEN 12
                            ELSE 0
                        END
                    ) < %s)
                )
                AND project_code = %s
                AND status != 'approved'
                AND id != %s
                """,
                (year, year, month_num, project_code, exclude_report_id),
                fetch_one=True,
            )
        else:
            unapproved = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE (
                    (year < %s) OR
                    (year = %s AND (
                        CASE LOWER(month)
                            WHEN 'january' THEN 1
                            WHEN 'february' THEN 2
                            WHEN 'march' THEN 3
                            WHEN 'april' THEN 4
                            WHEN 'may' THEN 5
                            WHEN 'june' THEN 6
                            WHEN 'july' THEN 7
                            WHEN 'august' THEN 8
                            WHEN 'september' THEN 9
                            WHEN 'october' THEN 10
                            WHEN 'november' THEN 11
                            WHEN 'december' THEN 12
                            ELSE 0
                        END
                    ) < %s)
                )
                AND project_code = %s
                AND status != 'approved'
                """,
                (year, year, month_num, project_code),
                fetch_one=True,
            )
        return unapproved and unapproved.get("count", 0) > 0
    except mysql.connector.Error as e:
        print(f"Error checking unapproved reports: {e}")
        # On error, allow submission to avoid blocking users unnecessarily
        return False


def _check_reports_after_exist(month: str, year: int, project_code: str, exclude_report_id: int = None):
    """
    Check if there are any reports (pending or approved) AFTER the given month/year 
    for a specific project. Returns True if later reports exist.
    
    This prevents filling older months when newer months already have data,
    which would cause discrepancy in cumulative numbers.
    
    Args:
        month: Full month name (e.g. 'January')
        year: Year (integer)
        project_code: Project code to filter by
        exclude_report_id: Optional report ID to exclude from the check (useful for updates)
    """
    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }
    
    month_num = month_map.get(month.lower())
    if not month_num:
        return False
    
    try:
        # Check for any reports AFTER this month/year for this project
        if exclude_report_id:
            later_reports = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE (
                    (year > %s) OR
                    (year = %s AND (
                        CASE LOWER(month)
                            WHEN 'january' THEN 1
                            WHEN 'february' THEN 2
                            WHEN 'march' THEN 3
                            WHEN 'april' THEN 4
                            WHEN 'may' THEN 5
                            WHEN 'june' THEN 6
                            WHEN 'july' THEN 7
                            WHEN 'august' THEN 8
                            WHEN 'september' THEN 9
                            WHEN 'october' THEN 10
                            WHEN 'november' THEN 11
                            WHEN 'december' THEN 12
                            ELSE 0
                        END
                    ) > %s)
                )
                AND project_code = %s
                AND status IN ('pending', 'approved')
                AND id != %s
                """,
                (year, year, month_num, project_code, exclude_report_id),
                fetch_one=True,
            )
        else:
            later_reports = execute_query(
                """
                SELECT COUNT(*) AS count
                FROM hse_reports
                WHERE (
                    (year > %s) OR
                    (year = %s AND (
                        CASE LOWER(month)
                            WHEN 'january' THEN 1
                            WHEN 'february' THEN 2
                            WHEN 'march' THEN 3
                            WHEN 'april' THEN 4
                            WHEN 'may' THEN 5
                            WHEN 'june' THEN 6
                            WHEN 'july' THEN 7
                            WHEN 'august' THEN 8
                            WHEN 'september' THEN 9
                            WHEN 'october' THEN 10
                            WHEN 'november' THEN 11
                            WHEN 'december' THEN 12
                            ELSE 0
                        END
                    ) > %s)
                )
                AND project_code = %s
                AND status IN ('pending', 'approved')
                """,
                (year, year, month_num, project_code),
                fetch_one=True,
            )
        return later_reports and later_reports.get("count", 0) > 0
    except mysql.connector.Error as e:
        print(f"Error checking later reports: {e}")
        # On error, allow submission to avoid blocking users unnecessarily
        return False


@app.route("/api/hse/unapproved_before", methods=["GET"])
@require_safety_officer
def hse_unapproved_before():
    """
    Check if there are any unapproved (pending or rejected) reports before
    the selected month/year for a specific project.

    This is used to show a clear warning message on the form so that users
    can get earlier months approved to avoid discrepancies in cumulative
    numbers.

    Returns:
        {
            "has_unapproved": bool,
            "reports": [
                {"month": "January", "year": 2025, "status": "pending", "report_number": "HSE-2025-01-001"},
                ...
            ]
        }
    """
    month = request.args.get("month", "").strip()
    year = request.args.get("year", "").strip()
    project_code = request.args.get("project_code", "").strip()

    if not project_code:
        return jsonify({"error": "project_code required"}), 400
    if not month or not year:
        return jsonify({"has_unapproved": False}), 400

    try:
        year_int = int(year)
    except (TypeError, ValueError):
        return jsonify({"has_unapproved": False}), 400

    # Normalize month to full month name
    normalized_month = _normalize_month_name(month)
    if not normalized_month:
        return jsonify({"has_unapproved": False}), 400

    # Build numeric month for comparison
    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }
    month_num = month_map.get(normalized_month.lower())
    if not month_num:
        return jsonify({"has_unapproved": False}), 400

    try:
        rows = execute_query(
            """
            SELECT month, year, status, report_number
            FROM hse_reports
            WHERE (
                (year < %s) OR
                (year = %s AND (
                    CASE LOWER(month)
                        WHEN 'january' THEN 1
                        WHEN 'february' THEN 2
                        WHEN 'march' THEN 3
                        WHEN 'april' THEN 4
                        WHEN 'may' THEN 5
                        WHEN 'june' THEN 6
                        WHEN 'july' THEN 7
                        WHEN 'august' THEN 8
                        WHEN 'september' THEN 9
                        WHEN 'october' THEN 10
                        WHEN 'november' THEN 11
                        WHEN 'december' THEN 12
                        ELSE 0
                    END
                ) < %s)
            )
            AND project_code = %s
            AND status != 'approved'
            ORDER BY year, 
                     CASE LOWER(month)
                        WHEN 'january' THEN 1
                        WHEN 'february' THEN 2
                        WHEN 'march' THEN 3
                        WHEN 'april' THEN 4
                        WHEN 'may' THEN 5
                        WHEN 'june' THEN 6
                        WHEN 'july' THEN 7
                        WHEN 'august' THEN 8
                        WHEN 'september' THEN 9
                        WHEN 'october' THEN 10
                        WHEN 'november' THEN 11
                        WHEN 'december' THEN 12
                        ELSE 0
                     END
            """,
            (year_int, year_int, month_num, project_code),
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching unapproved reports list: {e}")
        return jsonify({"has_unapproved": False, "reports": []}), 500

    reports = rows or []
    return jsonify(
        {
            "has_unapproved": bool(reports),
            "reports": reports,
        }
    )


@app.route("/api/hse/reports_after", methods=["GET"])
@require_safety_officer
def hse_reports_after():
    """
    Check if there are any reports (pending or approved) AFTER the selected 
    month/year for a specific project. Returns the list of later reports.
    
    This prevents filling older months when newer months already have data,
    which would cause discrepancy in cumulative numbers.
    """
    month = request.args.get("month", "").strip()
    year = request.args.get("year", "").strip()
    project_code = request.args.get("project_code", "").strip()

    if not month or not year or not project_code:
        return jsonify({"has_later_reports": False}), 400

    # Normalize month to full month name
    normalized_month = _normalize_month_name(month)
    if not normalized_month:
        return jsonify({"has_later_reports": False}), 400

    try:
        year_int = int(year)
    except (TypeError, ValueError):
        return jsonify({"has_later_reports": False}), 400

    month_map = {
        "january": 1,
        "february": 2,
        "march": 3,
        "april": 4,
        "may": 5,
        "june": 6,
        "july": 7,
        "august": 8,
        "september": 9,
        "october": 10,
        "november": 11,
        "december": 12,
    }
    month_num = month_map.get(normalized_month.lower())
    if not month_num:
        return jsonify({"has_later_reports": False}), 400

    try:
        rows = execute_query(
            """
            SELECT month, year, status, report_number
            FROM hse_reports
            WHERE (
                (year > %s) OR
                (year = %s AND (
                    CASE LOWER(month)
                        WHEN 'january' THEN 1
                        WHEN 'february' THEN 2
                        WHEN 'march' THEN 3
                        WHEN 'april' THEN 4
                        WHEN 'may' THEN 5
                        WHEN 'june' THEN 6
                        WHEN 'july' THEN 7
                        WHEN 'august' THEN 8
                        WHEN 'september' THEN 9
                        WHEN 'october' THEN 10
                        WHEN 'november' THEN 11
                        WHEN 'december' THEN 12
                        ELSE 0
                    END
                ) > %s)
            )
            AND project_code = %s
            AND status IN ('pending', 'approved')
            ORDER BY year, 
                     CASE LOWER(month)
                        WHEN 'january' THEN 1
                        WHEN 'february' THEN 2
                        WHEN 'march' THEN 3
                        WHEN 'april' THEN 4
                        WHEN 'may' THEN 5
                        WHEN 'june' THEN 6
                        WHEN 'july' THEN 7
                        WHEN 'august' THEN 8
                        WHEN 'september' THEN 9
                        WHEN 'october' THEN 10
                        WHEN 'november' THEN 11
                        WHEN 'december' THEN 12
                        ELSE 0
                     END
            """,
            (year_int, year_int, month_num, project_code),
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching later reports list: {e}")
        return jsonify({"has_later_reports": False, "reports": []}), 500

    reports = rows or []
    return jsonify(
        {
            "has_later_reports": bool(reports),
            "reports": reports,
        }
    )


@app.route("/api/hse/config", methods=["GET"])
@require_role("safety_officer", "project_manager", "admin")
def hse_config():
    try:
        rows = execute_query(
            """
            SELECT id, config_key, config_value, config_type
            FROM admin_config
            WHERE config_type IN ('prepared_by', 'approved_by', 'contractor', 'name_of_work', 'project')
            ORDER BY id
            """,
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching HSE config: {e}")
        return jsonify({"error": "Failed to fetch configuration"}), 500

    prepared_by = []
    approved_by = []
    contractors = []
    work_names = []
    projects = []

    for row in rows or []:
        if row["config_type"] in ("prepared_by", "approved_by"):
            try:
                value = json.loads(row["config_value"] or "{}")
            except (json.JSONDecodeError, TypeError):
                value = {}
            entry = {
                "id": row["id"],
                "name": value.get("name", ""),
                "designation": value.get("designation", ""),
            }
            if row["config_type"] == "prepared_by":
                prepared_by.append(entry)
            else:
                approved_by.append(entry)
        elif row["config_type"] == "name_of_work":
            work_names.append(
                {
                    "id": row["id"],
                    "work_name": row["config_value"],
                }
            )
        elif row["config_type"] == "contractor":
            contractors.append(
                {
                    "id": row["id"],
                    "contractor_name": row["config_value"],
                }
            )
        elif row["config_type"] == "project":
            try:
                value = json.loads(row["config_value"] or "{}")
            except (json.JSONDecodeError, TypeError):
                value = {}
            projects.append(
                {
                    "id": row["id"],
                    "project_code": value.get("code", ""),
                    "project_name": value.get("name", ""),
                }
            )

    return jsonify(
        {
            "prepared_by": prepared_by,
            "approved_by": approved_by,
            "contractors": contractors,
            "work_names": work_names,
            "projects": projects,
        }
    )


@app.route("/api/hse/check_month", methods=["GET"])
@require_safety_officer
def check_month_exists():
    """
    Check if a report already exists for the given project_code and month/year.
    Returns: {exists: bool, report_id: int|null, status: str|null}
    """
    month = request.args.get("month", "").strip()
    year = request.args.get("year", "").strip()
    project_code = request.args.get("project_code", "").strip()
    
    if not project_code:
        return jsonify({"error": "project_code required"}), 400
    if not month or not year:
        return jsonify({"exists": False}), 400
    
    try:
        year_int = int(year)
    except (TypeError, ValueError):
        return jsonify({"exists": False}), 400
    
    # Normalize month to full month name
    normalized_month = _normalize_month_name(month)
    if not normalized_month:
        return jsonify({"exists": False}), 400
    
    try:
        existing = execute_query(
            """
            SELECT id, status, report_number
            FROM hse_reports
            WHERE project_code = %s AND month = %s AND year = %s
            LIMIT 1
            """,
            (project_code, normalized_month, year_int),
            fetch_one=True,
        )
        
        if existing:
            return jsonify({
                "exists": True,
                "report_id": existing["id"],
                "status": existing["status"],
                "report_number": existing["report_number"]
            })
        else:
            return jsonify({"exists": False})
    except mysql.connector.Error as e:
        print(f"Error checking month existence: {e}")
        return jsonify({"exists": False}), 500


@app.route("/api/hse/previous_month", methods=["GET"])
@require_role("safety_officer", "project_manager", "admin")
def hse_previous_month():
    month = request.args.get("month", "").strip()
    year = request.args.get("year", "").strip()
    project_code = request.args.get("project_code", "").strip()

    if not project_code:
        return jsonify({"error": "project_code is required"}), 400

    try:
        # If month is in 'YYYY-MM' format, prefer the embedded year.
        if (
            len(month) == 7
            and month[4] == "-"
            and month[:4].isdigit()
            and month[5:].isdigit()
        ):
            year_int = int(month[:4])
        else:
            year_int = int(year)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid year"}), 400

    prev_month, prev_year = _get_previous_month(month, year_int)
    if not prev_month:
        return jsonify({"error": "Invalid month"}), 400

    try:
        row = execute_query(
            """
            SELECT report_data
            FROM hse_reports
            WHERE month = %s AND year = %s AND project_code = %s AND status IN ('approved', 'pending')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (prev_month, prev_year, project_code),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching previous HSE report: {e}")
        return jsonify({"error": "Failed to fetch previous report"}), 500

    if not row or not row.get("report_data"):
        return jsonify({})

    try:
        report_data = json.loads(row["report_data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        report_data = {}

    cumulative_only = {}
    for key, value in (report_data or {}).items():
        if isinstance(value, dict):
            cumulative_only[key] = value.get("cumulative", 0)

    return jsonify(cumulative_only)


@app.route("/api/hse/submit", methods=["POST"])
@require_safety_officer
def submit_hse_report():
    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )

    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}

    required_fields = [
        "month",
        "year",
        "name_of_work",
        "contractor_name",
        "status_date",
        "report_data",
        "project_code",
    ]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            ),
            400,
        )

    raw_month = data.get("month").strip()
    year = data.get("year")
    name_of_work = data.get("name_of_work").strip()
    wo_number = (data.get("wo_number") or "").strip()
    contractor_name = data.get("contractor_name").strip()
    status_date = data.get("status_date").strip()
    remarks = (data.get("remarks") or "").strip() or None
    current_report_data = data.get("report_data") or {}
    project_code = data.get("project_code").strip()

    # Validate project_code exists in admin_config
    try:
        project_exists = execute_query(
            """
            SELECT id FROM admin_config 
            WHERE config_type = 'project' AND JSON_UNQUOTE(JSON_EXTRACT(config_value, '$.code')) = %s
            LIMIT 1
            """,
            (project_code,),
            fetch_one=True,
        )
        if not project_exists:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Invalid project code: {project_code}",
                    }
                ),
                400,
            )
    except mysql.connector.Error as e:
        print(f"Error validating project code: {e}")
        return jsonify({"success": False, "message": "Failed to validate project code"}), 500

    normalized_month = _normalize_month_name(raw_month)
    if not normalized_month:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid month format. Expected month name, numeric month, or 'YYYY-MM'.",
                }
            ),
            400,
        )
    month = normalized_month
    user_id = session.get("user_id")

    # Generate report number in the format "OH&S-HSE-01-YY-XX"
    # YY = last two digits of the year, XX = 2‑digit month (01‑12)
    try:
        year_int = int(year)
    except (TypeError, ValueError):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid year value.",
                }
            ),
            400,
        )

    # Map normalized month name back to month number 1‑12
    month_lookup = {
        "January": 1,
        "February": 2,
        "March": 3,
        "April": 4,
        "May": 5,
        "June": 6,
        "July": 7,
        "August": 8,
        "September": 9,
        "October": 10,
        "November": 11,
        "December": 12,
    }
    month_num = month_lookup.get(month)
    if not month_num:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Unable to determine month number for report number generation.",
                }
            ),
            400,
        )

    year_suffix = str(year_int)[-2:]
    month_suffix = f"{month_num:02d}"
    report_number = f"OH&S-HSE-01-{year_suffix}-{month_suffix}"
    try:
        # Check if report number already exists for this project
        # Same report_number is allowed for different projects
        existing = execute_query(
            "SELECT id FROM hse_reports WHERE report_number = %s AND project_code = %s",
            (report_number, project_code),
            fetch_one=True,
        )
        if existing:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Report number already exists for project {project_code}",
                    }
                ),
                400,
            )

        # Check if project already has a report for this month/year
        existing_month = execute_query(
            """
            SELECT id, status, report_number
            FROM hse_reports
            WHERE project_code = %s AND month = %s AND year = %s
            LIMIT 1
            """,
            (project_code, month, int(year)),
            fetch_one=True,
        )
        if existing_month:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"A report for project {project_code} already exists for {month} {year}. Report: {existing_month.get('report_number', 'N/A')} (Status: {existing_month.get('status', 'unknown')})",
                    }
                ),
                400,
            )

        # Check if there are any unapproved reports before this month/year for this project
        if _check_unapproved_reports_before(month, int(year), project_code):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Cannot submit new report: There are previous reports that are not approved yet. Please get it approved First to Avoid any Discrepancy in Cumulative Numbers.",
                    }
                ),
                400,
            )

        # Check if there are any reports AFTER this month/year for this project
        # This prevents filling older months when newer months already have data
        if _check_reports_after_exist(month, int(year), project_code):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Cannot submit report for this month: A report for a later month already exists for this project. Filling earlier months would cause discrepancy in Cumulative Numbers.",
                    }
                ),
                400,
            )

        prev_month, prev_year = _get_previous_month(raw_month, int(year))
        previous_data = {}
        if prev_month and prev_year is not None:
            prev_row = execute_query(
                """
                SELECT report_data
                FROM hse_reports
                WHERE month = %s AND year = %s AND project_code = %s AND status IN ('approved', 'pending')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (prev_month, prev_year, project_code),
                fetch_one=True,
            )
            if prev_row and prev_row.get("report_data"):
                try:
                    previous_data = json.loads(prev_row["report_data"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    previous_data = {}

        final_report_data = calculate_cumulative_values(
            current_report_data, previous_data or {}
        )

        execute_query(
            """
            INSERT INTO hse_reports (
                report_number,
                project_code,
                month,
                year,
                name_of_work,
                wo_number,
                contractor_name,
                status_date,
                prepared_by_id,
                report_data,
                remarks,
                status,
                approved_by_id,
                rejection_comment
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', NULL, NULL)
            """,
            (
                report_number,
                project_code,
                month,
                year,
                name_of_work,
                wo_number,
                contractor_name,
                status_date,
                session.get("user_id"),
                json.dumps(final_report_data),
                remarks,
            ),
            commit=True,
        )

        row = execute_query("SELECT LAST_INSERT_ID() AS id", fetch_one=True)
        new_id = row["id"] if row else None

        return jsonify(
            {
                "success": True,
                "message": "Report submitted successfully",
                "report_id": new_id,
            }
        )
    except mysql.connector.Error as e:
        print(f"Error submitting HSE report: {e}")
        message = "Failed to submit report"
        if "Duplicate" in str(e):
            message = "Duplicate report or constraint violation"
        return jsonify({"success": False, "message": message}), 500


@app.route("/api/hse/reports", methods=["GET"])
@require_safety_officer
def hse_reports_list():
    user_id = session.get("user_id")
    try:
        rows = execute_query(
            """
            SELECT
                r.id,
                r.report_number,
                r.project_code,
                r.month,
                r.year,
                r.name_of_work,
                r.contractor_name,
                r.status,
                r.status_date,
                r.created_at,
                r.updated_at,
                r.rejection_comment,
                u.full_name AS approved_by_name
            FROM hse_reports r
            LEFT JOIN users u ON r.approved_by_id = u.id
            WHERE r.prepared_by_id = %s
            ORDER BY r.created_at DESC
            """,
            (user_id,),
            fetch_all=True,
        )
        return jsonify(rows or [])
    except mysql.connector.Error as e:
        print(f"Error fetching HSE reports list: {e}")
        return jsonify({"error": "Failed to fetch reports"}), 500


@app.route("/api/hse/report/<int:report_id>", methods=["GET"])
@require_role("safety_officer", "project_manager", "admin")
def hse_report_detail(report_id):
    try:
        row = execute_query(
            """
            SELECT
                r.*,
                u.full_name AS prepared_by_name,
                u.email AS prepared_by_email,
                u.designation AS prepared_by_designation
            FROM hse_reports r
            LEFT JOIN users u ON r.prepared_by_id = u.id
            WHERE r.id = %s
            """,
            (report_id,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching HSE report detail: {e}")
        return jsonify({"error": "Failed to fetch report"}), 500

    if not row:
        return jsonify({"error": "Report not found"}), 404

    role = session.get("role")
    user_id = session.get("user_id")
    if role == "safety_officer" and row.get("prepared_by_id") != user_id:
        return jsonify({"error": "Forbidden"}), 403

    try:
        if row.get("report_data"):
            row["report_data"] = json.loads(row["report_data"] or "{}")
        else:
            row["report_data"] = {}
    except (json.JSONDecodeError, TypeError):
        row["report_data"] = {}

    return jsonify(row)


@app.route("/api/hse/download/<int:report_id>", methods=["GET"])
@require_role("safety_officer", "project_manager", "admin")
def hse_report_download(report_id):
    """
    Generate a PDF for an approved HSE report using xhtml2pdf and stream it to the client.
    Only approved reports are eligible for download.
    """
    role = session.get("role")
    user_id = session.get("user_id")

    try:
        row = execute_query(
            """
            SELECT
                r.*,
                pb.username AS prepared_by_username,
                pb.full_name AS prepared_by_full_name,
                pb.email AS prepared_by_email,
                pb.profile_pic AS prepared_by_profile_pic,
                ab.username AS approved_by_username,
                ab.full_name AS approved_by_full_name,
                ab.email AS approved_by_email,
                ab.profile_pic AS approved_by_profile_pic
            FROM hse_reports r
            LEFT JOIN users pb ON r.prepared_by_id = pb.id
            LEFT JOIN users ab ON r.approved_by_id = ab.id
            WHERE r.id = %s
            """,
            (report_id,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching HSE report for PDF download: {e}")
        return jsonify({"error": "Failed to fetch report"}), 500

    if not row:
        return jsonify({"error": "Report not found"}), 404

    # Safety Officer can only download their own reports
    if role == "safety_officer" and row.get("prepared_by_id") != user_id:
        return jsonify({"error": "Forbidden"}), 403

    if (row.get("status") or "").lower() != "approved":
        return (
            jsonify({"error": "Only approved reports can be downloaded"}),
            403,
        )

    # Parse report_data JSON
    try:
        if row.get("report_data"):
            row["report_data"] = json.loads(row["report_data"] or "{}")
        else:
            row["report_data"] = {}
    except (json.JSONDecodeError, TypeError):
        row["report_data"] = {}

    # Build prepared_by and approved_by user dicts
    prepared_by = {
        "username": row.get("prepared_by_username"),
        "full_name": row.get("prepared_by_full_name"),
        "email": row.get("prepared_by_email"),
        "profile_pic": row.get("prepared_by_profile_pic"),
    }
    if not any(prepared_by.values()):
        prepared_by = None

    approved_by = {
        "username": row.get("approved_by_username"),
        "full_name": row.get("approved_by_full_name"),
        "email": row.get("approved_by_email"),
        "profile_pic": row.get("approved_by_profile_pic"),
    }
    if not any(approved_by.values()):
        approved_by = None

    generated_at = datetime.utcnow()

    # Fetch project name from admin_config table
    project_name = None
    if row.get("project_code"):
        try:
            project_row = execute_query(
                """
                SELECT config_value 
                FROM admin_config 
                WHERE config_type = 'project' 
                AND JSON_UNQUOTE(JSON_EXTRACT(config_value, '$.code')) = %s
                LIMIT 1
                """,
                (row.get("project_code"),),
                fetch_one=True
            )
            if project_row:
                project_data = json.loads(project_row.get("config_value", "{}"))
                project_name = project_data.get("name", "")
        except Exception as e:
            print(f"Error fetching project name: {e}")

    # Resolve absolute filesystem paths for logos so xhtml2pdf can load them
    logo_path = os.path.join(app.root_path, "static", "images", "simonindia_logo.png")
    adventz_logo_path = os.path.join(app.root_path, "static", "images", "adventz_logo.png")

    try:
        html_string = render_template(
            "report_pdf.html",
            report=row,
            prepared_by=prepared_by,
            approved_by=approved_by,
            generated_at=generated_at,
            project_name=project_name,
            logo_path=logo_path,
            adventz_logo_path=adventz_logo_path,
        )
    except Exception as e:
        print(f"Error rendering HSE report PDF template: {e}")
        return jsonify({"error": "Failed to render PDF template"}), 500

    try:
        pdf_buffer = BytesIO()
        pisa_status = pisa.CreatePDF(
            html_string,
            dest=pdf_buffer,
            encoding='utf-8'
        )
        if pisa_status.err:
            print(f"xhtml2pdf PDF generation error: {pisa_status.err}")
            return jsonify({"error": "PDF generation failed"}), 500
        pdf_bytes = pdf_buffer.getvalue()
        pdf_buffer.close()
    except Exception as e:
        print(f"xhtml2pdf PDF generation error: {e}")
        return jsonify({"error": "PDF generation failed"}), 500

    filename = f'HSE_Report_{row.get("report_number", report_id)}_{row.get("month", "")}_{row.get("year", "")}.pdf'
    
    # Clean filename to avoid issues
    filename = filename.replace(" ", "_").replace("/", "-")

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf",
            "Content-Length": str(len(pdf_bytes)),
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        },
    )


@app.route("/api/hse/pending_reports", methods=["GET"])
@require_project_manager
def hse_pending_reports():
    """
    List HSE reports for project managers, filtered by month/year/contractor.
    Status is always constrained to 'pending'.
    """
    month = (request.args.get("month") or "").strip()
    year = (request.args.get("year") or "").strip()
    contractor_name = (request.args.get("contractor_name") or "").strip()

    where_clauses = ["r.status = %s"]
    params = ["pending"]

    if month:
        normalized_month = _normalize_month_name(month)
        if not normalized_month:
            return jsonify({"error": "Invalid month parameter"}), 400
        where_clauses.append("r.month = %s")
        params.append(normalized_month)
    if year:
        try:
            year_int = int(year)
            where_clauses.append("r.year = %s")
            params.append(year_int)
        except ValueError:
            return jsonify({"error": "Invalid year parameter"}), 400
    if contractor_name:
        where_clauses.append("r.contractor_name = %s")
        params.append(contractor_name)

    where_sql = " AND ".join(where_clauses)

    try:
        rows = execute_query(
            f"""
            SELECT
                r.id,
                r.report_number,
                r.project_code,
                r.month,
                r.year,
                r.name_of_work,
                r.contractor_name,
                r.status_date,
                r.created_at,
                u.full_name AS prepared_by_name,
                u.email AS prepared_by_email
            FROM hse_reports r
            JOIN users u ON r.prepared_by_id = u.id
            WHERE {where_sql}
            ORDER BY r.created_at DESC
            """,
            tuple(params),
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching pending HSE reports: {e}")
        return jsonify({"error": "Failed to fetch pending reports"}), 500

    return jsonify(rows or [])


@app.route("/api/hse/approved_reports", methods=["GET"])
@require_project_manager
def hse_approved_reports():
    """
    List approved HSE reports for project managers, filtered by month/year/contractor.
    """
    month = (request.args.get("month") or "").strip()
    year = (request.args.get("year") or "").strip()
    contractor_name = (request.args.get("contractor_name") or "").strip()

    where_clauses = ["r.status = %s"]
    params = ["approved"]

    if month:
        normalized_month = _normalize_month_name(month)
        if not normalized_month:
            return jsonify({"error": "Invalid month parameter"}), 400
        where_clauses.append("r.month = %s")
        params.append(normalized_month)
    if year:
        try:
            year_int = int(year)
            where_clauses.append("r.year = %s")
            params.append(year_int)
        except ValueError:
            return jsonify({"error": "Invalid year parameter"}), 400
    if contractor_name:
        where_clauses.append("r.contractor_name = %s")
        params.append(contractor_name)

    where_sql = " AND ".join(where_clauses)

    try:
        rows = execute_query(
            f"""
            SELECT
                r.id,
                r.report_number,
                r.project_code,
                r.month,
                r.year,
                r.name_of_work,
                r.contractor_name,
                r.status_date,
                r.created_at,
                r.updated_at,
                u.full_name AS prepared_by_name,
                u.email AS prepared_by_email
            FROM hse_reports r
            JOIN users u ON r.prepared_by_id = u.id
            WHERE {where_sql}
            ORDER BY r.updated_at DESC, r.created_at DESC
            """,
            tuple(params),
            fetch_all=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching approved HSE reports: {e}")
        return jsonify({"error": "Failed to fetch approved reports"}), 500

    return jsonify(rows or [])


@app.route("/api/hse/project_analytics", methods=["GET"])
@require_project_manager
def hse_project_analytics():
    """
    Fetch project-specific cumulative analytics.
    Returns the latest approved report's cumulative values for:
    - Total Safe Man-hours
    - LTI Count (fatalities + other_lti)
    - Frequency Rate
    - Severity Rate
    - Pending NCs
    """
    project_code = request.args.get("project_code", "").strip()

    if not project_code:
        return jsonify({"error": "project_code is required"}), 400

    try:
        # Fetch the latest approved report for this project
        row = execute_query(
            """
            SELECT report_data, month, year, report_number
            FROM hse_reports
            WHERE project_code = %s AND status = 'approved'
            ORDER BY year DESC,
                     FIELD(month, 'January', 'February', 'March', 'April', 'May', 'June',
                           'July', 'August', 'September', 'October', 'November', 'December') DESC
            LIMIT 1
            """,
            (project_code,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching project analytics: {e}")
        return jsonify({"error": "Failed to fetch analytics"}), 500

    if not row or not row.get("report_data"):
        return jsonify(
            {"has_data": False, "message": "No approved reports found for this project"}
        )

    try:
        report_data = json.loads(row["report_data"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return jsonify({"error": "Invalid report data"}), 500

    # Extract cumulative values
    safe_manhours = report_data.get("safe_manhours", {}).get("cumulative", 0)
    fatalities = report_data.get("fatalities", {}).get("cumulative", 0)
    other_lti = report_data.get("other_lti", {}).get("cumulative", 0)
    lti_count = fatalities + other_lti
    frequency_rate = report_data.get("frequency_rate", {}).get("cumulative", 0)
    severity_rate = report_data.get("severity_rate", {}).get("cumulative", 0)
    pending_ncs = report_data.get("pending_ncs", {}).get("cumulative", 0)

    return jsonify(
        {
            "has_data": True,
            "project_code": project_code,
            "latest_report": {
                "month": row.get("month"),
                "year": row.get("year"),
                "report_number": row.get("report_number"),
            },
            "metrics": {
                "safe_manhours": safe_manhours,
                "lti_count": lti_count,
                "frequency_rate": frequency_rate,
                "severity_rate": severity_rate,
                "pending_ncs": pending_ncs,
            },
        }
    )


@app.route("/api/hse/approve/<int:report_id>", methods=["POST"])
@require_project_manager
def approve_hse_report(report_id):
    """
    Approve a pending HSE report.
    """
    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )

    try:
        report = execute_query(
            """
            SELECT id, report_number, month, year, status, prepared_by_id
            FROM hse_reports
            WHERE id = %s
            """,
            (report_id,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching report for approval: {e}")
        return jsonify({"success": False, "message": "Failed to load report"}), 500

    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404

    if report.get("status") != "pending":
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Only pending reports can be approved",
                }
            ),
            400,
        )

    current_user_id = session.get("user_id")

    try:
        execute_query(
            """
            UPDATE hse_reports
            SET status = 'approved',
                approved_by_id = %s,
                rejection_comment = NULL,
                updated_at = NOW()
            WHERE id = %s
            """,
            (current_user_id, report_id),
            commit=True,
        )
    except mysql.connector.Error as e:
        print(f"Error approving HSE report: {e}")
        return (
            jsonify({"success": False, "message": "Failed to approve report"}),
            500,
        )

    # Send notification to Safety Officer
    try:
        msg = f"Your HSE report {report['report_number']} for {report['month']} {report['year']} has been approved"
        add_notification(
            report["prepared_by_id"],
            msg,
            report_id,
            "approval",
        )
    except Exception as e:
        print(f"Failed to add approval notification: {e}")

    return jsonify({"success": True, "message": "Report approved successfully"})


@app.route("/api/hse/reject/<int:report_id>", methods=["POST"])
@require_project_manager
def reject_hse_report(report_id):
    """
    Reject a pending HSE report with a rejection comment.
    """
    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    rejection_comment = (data.get("rejection_comment") or "").strip()

    if not rejection_comment or len(rejection_comment) < 10:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Rejection comment must be at least 10 characters",
                }
            ),
            400,
        )

    try:
        report = execute_query(
            """
            SELECT id, report_number, month, year, status, prepared_by_id
            FROM hse_reports
            WHERE id = %s
            """,
            (report_id,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching report for rejection: {e}")
        return jsonify({"success": False, "message": "Failed to load report"}), 500

    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404

    if report.get("status") != "pending":
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Only pending reports can be rejected",
                }
            ),
            400,
        )

    current_user_id = session.get("user_id")

    try:
        execute_query(
            """
            UPDATE hse_reports
            SET status = 'rejected',
                approved_by_id = %s,
                rejection_comment = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (current_user_id, rejection_comment, report_id),
            commit=True,
        )
    except mysql.connector.Error as e:
        print(f"Error rejecting HSE report: {e}")
        return (
            jsonify({"success": False, "message": "Failed to reject report"}),
            500,
        )

    # Send notification to Safety Officer
    try:
        preview = rejection_comment[:50] + ("..." if len(rejection_comment) > 50 else "")
        msg = (
            f"Your HSE report {report['report_number']} for {report['month']} {report['year']} "
            f"has been rejected. Reason: {preview}"
        )
        add_notification(
            report["prepared_by_id"],
            msg,
            report_id,
            "rejection",
        )
    except Exception as e:
        print(f"Failed to add rejection notification: {e}")

    return jsonify({"success": True, "message": "Report rejected successfully"})


@app.route("/api/hse/update/<int:report_id>", methods=["POST"])
@require_safety_officer
def update_hse_report(report_id):
    if not verify_csrf_header():
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid or missing CSRF token",
                }
            ),
            400,
        )

    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}

    required_fields = [
        "month",
        "year",
        "name_of_work",
        "contractor_name",
        "status_date",
        "report_data",
        "project_code",
    ]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Missing required fields: {', '.join(missing)}",
                }
            ),
            400,
        )

    user_id = session.get("user_id")
    project_code = data.get("project_code").strip()

    # Validate project_code exists in admin_config
    try:
        project_exists = execute_query(
            """
            SELECT id FROM admin_config 
            WHERE config_type = 'project' AND JSON_UNQUOTE(JSON_EXTRACT(config_value, '$.code')) = %s
            LIMIT 1
            """,
            (project_code,),
            fetch_one=True,
        )
        if not project_exists:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Invalid project code: {project_code}",
                    }
                ),
                400,
            )
    except mysql.connector.Error as e:
        print(f"Error validating project code: {e}")
        return jsonify({"success": False, "message": "Failed to validate project code"}), 500

    try:
        existing = execute_query(
            """
            SELECT id, prepared_by_id, status, project_code
            FROM hse_reports
            WHERE id = %s AND prepared_by_id = %s
            """,
            (report_id, user_id),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching existing HSE report: {e}")
        return jsonify({"success": False, "message": "Failed to load report"}), 500

    if not existing:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Report not found or access denied",
                }
            ),
            404,
        )

    if existing.get("status") != "rejected":
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Can only edit rejected reports",
                }
            ),
            400,
        )

    # Preserve existing report number; do not allow client to change it
    report_row = execute_query(
        "SELECT report_number FROM hse_reports WHERE id = %s",
        (report_id,),
        fetch_one=True,
    )
    if not report_row or not report_row.get("report_number"):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Existing report number not found",
                }
            ),
            404,
        )
    report_number = report_row["report_number"]
    raw_month = data.get("month").strip()
    year = data.get("year")
    name_of_work = data.get("name_of_work").strip()
    wo_number = (data.get("wo_number") or "").strip()
    contractor_name = data.get("contractor_name").strip()
    status_date = data.get("status_date").strip()
    remarks = (data.get("remarks") or "").strip() or None
    current_report_data = data.get("report_data") or {}

    normalized_month = _normalize_month_name(raw_month)
    if not normalized_month:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Invalid month format. Expected month name, numeric month, or 'YYYY-MM'.",
                }
            ),
            400,
        )
    month = normalized_month

    try:
        # Prevent duplicate report_number for the same project (different report).
        # Same report_number is allowed across different projects.
        conflict = execute_query(
            """
            SELECT id
            FROM hse_reports
            WHERE report_number = %s AND project_code = %s AND id != %s
            """,
            (report_number, project_code, report_id),
            fetch_one=True,
        )
        if conflict:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Report number already exists for project {project_code}",
                    }
                ),
                400,
            )

        # Check if project already has a report for this month/year (excluding current report)
        existing_month = execute_query(
            """
            SELECT id, status, report_number
            FROM hse_reports
            WHERE project_code = %s AND month = %s AND year = %s AND id != %s
            LIMIT 1
            """,
            (project_code, month, int(year), report_id),
            fetch_one=True,
        )
        if existing_month:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"A report for project {project_code} already exists for {month} {year}. Report: {existing_month.get('report_number', 'N/A')} (Status: {existing_month.get('status', 'unknown')})",
                    }
                ),
                400,
            )

        # Check if there are any unapproved reports before this month/year for this project
        # Exclude the current report from the check
        if _check_unapproved_reports_before(month, int(year), project_code, exclude_report_id=report_id):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Cannot update report: There are previous reports that are not approved yet. Please get it approved First to Avoid any Discrepancy in Cumulative Numbers.",
                    }
                ),
                400,
            )

        # Check if there are any reports AFTER this month/year for this project
        # Exclude the current report from the check
        if _check_reports_after_exist(month, int(year), project_code, exclude_report_id=report_id):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Cannot update report to this month: A report for a later month already exists for this project. Filling earlier months would cause discrepancy in Cumulative Numbers.",
                    }
                ),
                400,
            )

        prev_month, prev_year = _get_previous_month(raw_month, int(year))
        previous_data = {}
        if prev_month and prev_year is not None:
            prev_row = execute_query(
                """
                SELECT report_data
                FROM hse_reports
                WHERE month = %s AND year = %s AND project_code = %s AND status = 'approved'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (prev_month, prev_year, project_code),
                fetch_one=True,
            )
            if prev_row and prev_row.get("report_data"):
                try:
                    previous_data = json.loads(prev_row["report_data"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    previous_data = {}

        final_report_data = calculate_cumulative_values(
            current_report_data, previous_data or {}
        )

        execute_query(
            """
            UPDATE hse_reports
            SET
                report_number = %s,
                project_code = %s,
                month = %s,
                year = %s,
                name_of_work = %s,
                wo_number = %s,
                contractor_name = %s,
                status_date = %s,
                prepared_by_id = %s,
                report_data = %s,
                remarks = %s,
                status = 'pending',
                rejection_comment = NULL,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                report_number,
                project_code,
                month,
                year,
                name_of_work,
                wo_number,
                contractor_name,
                status_date,
                user_id,
                json.dumps(final_report_data),
                remarks,
                report_id,
            ),
            commit=True,
        )

        return jsonify(
            {
                "success": True,
                "message": "Report updated and resubmitted",
            }
        )
    except mysql.connector.Error as e:
        print(f"Error updating HSE report: {e}")
        message = "Failed to update report"
        if "Duplicate" in str(e):
            message = "Duplicate report or constraint violation"
        return jsonify({"success": False, "message": message}), 500


# ---------------------------------------------------------------------------
# Safety Officer & Project Manager Dashboards
# ---------------------------------------------------------------------------


@app.route("/safety_officer/dashboard")
@require_safety_officer_page
def safety_officer_dashboard():
    user = get_current_user()
    return render_template("safety_officer_dashboard.html", user=user)


@app.route("/safety_officer/form")
@require_safety_officer_page
def safety_officer_form():
    user = get_current_user()
    return render_template("hse_form.html", user=user)


@app.route("/project_manager/dashboard")
@require_project_manager_page
def project_manager_dashboard():
    user = get_current_user()
    return render_template("project_manager_dashboard.html", user=user)


@app.route("/project_manager/review/<int:report_id>")
@require_project_manager_page
def project_manager_review_report(report_id):
    """
    Render the review page for a specific HSE report.
    Only pending reports can be reviewed; others redirect back to the dashboard.
    """
    try:
        report = execute_query(
            """
            SELECT id, status
            FROM hse_reports
            WHERE id = %s
            """,
            (report_id,),
            fetch_one=True,
        )
    except mysql.connector.Error as e:
        print(f"Error fetching HSE report for review: {e}")
        report = None

    if not report:
        return redirect(url_for("project_manager_dashboard"))

    if report.get("status") != "pending":
        return redirect(url_for("project_manager_dashboard"))

    user = get_current_user()
    return render_template(
        "review_report.html",
        user=user,
        report_id=report_id,
    )


@app.route("/project_manager/analytics", methods=["GET"])
@require_project_manager_page
def project_manager_analytics():
    """
    Render the Manager Analytics page for project-specific cumulative metrics.
    """
    user = get_current_user()
    return render_template("manager_analytics.html", user=user)


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------


@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    create_connection_pool(pool_size=10)
    app.run(debug=True, host="0.0.0.0", port=5000)