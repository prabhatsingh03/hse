import os
import json
import time
from contextlib import contextmanager

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import mysql.connector
from mysql.connector import pooling, Error as MySQLError


# ---------------------------------------------------------------------------
# Environment & Basic Setup
# ---------------------------------------------------------------------------

# Load environment variables from .env in the HSE module directory
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "hse_reports_db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

# Temporary debug prints to verify that HSE/.env values are being loaded.
print(f"DB_HOST: {os.getenv('DB_HOST')}")
print(f"DB_USER: {os.getenv('DB_USER')}")
print(f"DB_NAME: {os.getenv('DB_NAME')}")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@simonindia.ai")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Simon@54321")

# Global connection pool (initialized after database creation)
connection_pool = None


# ---------------------------------------------------------------------------
# Connection Pool Helper
# ---------------------------------------------------------------------------

def create_connection_pool(pool_size: int = 5):
    """
    Create a MySQL connection pool for the HSE database.

    This should be called only after ensuring the database exists.
    """
    global connection_pool
    if connection_pool is None:
        connection_pool = pooling.MySQLConnectionPool(
            pool_name="hse_pool",
            pool_size=pool_size,
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
        )


@contextmanager
def get_db_connection(retries: int = 3, delay_seconds: float = 1.0):
    """
    Context manager to obtain a connection from the global pool with
    basic retry logic and automatic cleanup.
    """
    if connection_pool is None:
        raise RuntimeError("Connection pool has not been initialized. Call create_connection_pool() first.")

    attempt = 0
    conn = None
    try:
        while attempt < retries:
            try:
                conn = connection_pool.get_connection()
                break
            except MySQLError:
                attempt += 1
                if attempt >= retries:
                    raise
                time.sleep(delay_seconds)

        yield conn
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


# ---------------------------------------------------------------------------
# Database & Tables Creation
# ---------------------------------------------------------------------------

def create_database_if_not_exists():
    """
    Create the MySQL database (if missing) before initializing tables.
    This connects without specifying the database name.
    """
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT,
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _add_column_if_not_exists(cursor, table: str, column: str, column_def: str):
    """
    Helper to add a column to a table if it doesn't already exist.
    """
    cursor.execute(f"""
        SELECT COUNT(*) 
        FROM information_schema.COLUMNS 
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
    """, (DB_NAME, table, column))
    result = cursor.fetchone()
    if result and result[0] == 0:
        cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN {column} {column_def}")
        print(f"Added column '{column}' to table '{table}'")


def create_tables():
    """
    Create core tables for the HSE reporting system:
    - users: application users with roles (admin, safety_officer, project_manager)
    - hse_reports: HSE monthly reports with JSON payload for 32 parameters
    - admin_config: admin-managed dropdown configuration (prepared_by, approved_by, contractor)

    The JSON structure for report_data follows this pattern:
    {
        "staff_workmen": {"current": 0, "cumulative": 0},
        "safe_manhours": {"current": 0, "cumulative": 0},
        ...
        "legal_register": {"current": "No", "cumulative": "No"}
    }
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin', 'safety_officer', 'project_manager') NOT NULL,
                full_name VARCHAR(150) NOT NULL,
                designation VARCHAR(100),
                profile_pic VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )

        # hse_reports table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hse_reports (
                id INT PRIMARY KEY AUTO_INCREMENT,
                report_number VARCHAR(50) NOT NULL,
                project_code VARCHAR(50) NOT NULL,
                month VARCHAR(20) NOT NULL,
                year INT NOT NULL,
                name_of_work VARCHAR(255) NOT NULL,
                wo_number VARCHAR(100),
                contractor_name VARCHAR(150) NOT NULL,
                status_date DATE NOT NULL,
                prepared_by_id INT NOT NULL,
                approved_by_id INT,
                status ENUM('draft', 'pending', 'approved', 'rejected') DEFAULT 'draft',
                rejection_comment TEXT,
                remarks TEXT,
                report_data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_status (status),
                INDEX idx_month_year (month, year),
                INDEX idx_prepared_by (prepared_by_id),
                INDEX idx_approved_by (approved_by_id),
                INDEX idx_contractor (contractor_name),
                INDEX idx_project_code (project_code),
                INDEX idx_project_month_year (project_code, month, year),
                UNIQUE KEY uniq_project_month_year (project_code, month, year),
                CONSTRAINT fk_prepared_by
                    FOREIGN KEY (prepared_by_id) REFERENCES users(id)
                    ON DELETE RESTRICT ON UPDATE CASCADE,
                CONSTRAINT fk_approved_by
                    FOREIGN KEY (approved_by_id) REFERENCES users(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )

        # admin_config table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_config (
                id INT PRIMARY KEY AUTO_INCREMENT,
                config_key VARCHAR(100) NOT NULL,
                config_value TEXT NOT NULL,
                config_type VARCHAR(50) NOT NULL,
                description VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_config_key (config_key),
                INDEX idx_config_type (config_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )

        # Migration: Add remarks column to hse_reports if it doesn't exist
        _add_column_if_not_exists(cursor, "hse_reports", "remarks", "TEXT AFTER rejection_comment")

        # Migration: Add project_code column to hse_reports if it doesn't exist
        _add_column_if_not_exists(cursor, "hse_reports", "project_code", "VARCHAR(50) NOT NULL DEFAULT '' AFTER report_number")

        # Migration: Update unique constraint from (prepared_by_id, month, year) to (project_code, month, year)
        # Check if old constraint exists and drop it
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.TABLE_CONSTRAINTS
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'hse_reports' 
              AND CONSTRAINT_NAME = 'uniq_user_month_year'
        """, (DB_NAME,))
        result = cursor.fetchone()
        if result and result[0] > 0:
            cursor.execute("ALTER TABLE hse_reports DROP INDEX uniq_user_month_year")
            print("Dropped old constraint 'uniq_user_month_year'")

        # Check if new constraint exists, if not create it
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.TABLE_CONSTRAINTS
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'hse_reports' 
              AND CONSTRAINT_NAME = 'uniq_project_month_year'
        """, (DB_NAME,))
        result = cursor.fetchone()
        if result and result[0] == 0:
            # Before adding unique constraint, check for rows with blank project_code
            # that would cause duplicates on (project_code, month, year)
            cursor.execute("""
                SELECT COUNT(*) AS cnt
                FROM hse_reports
                WHERE project_code = '' OR project_code IS NULL
            """)
            blank_count = cursor.fetchone()
            if blank_count and blank_count[0] > 0:
                # Check for potential duplicates among rows with blank project_code
                cursor.execute("""
                    SELECT project_code, month, year, COUNT(*) AS cnt
                    FROM hse_reports
                    WHERE project_code = '' OR project_code IS NULL
                    GROUP BY project_code, month, year
                    HAVING COUNT(*) > 1
                """)
                duplicates = cursor.fetchall()
                if duplicates:
                    print("WARNING: Cannot add unique constraint 'uniq_project_month_year' - duplicate (project_code, month, year) found for blank project_code rows:")
                    for dup in duplicates:
                        print(f"  - project_code='{dup[0]}', month='{dup[1]}', year={dup[2]}, count={dup[3]}")
                    print("Please manually assign project_code values to these rows before running migration again.")
                else:
                    # No duplicates among blank rows, safe to add constraint
                    # But warn about blank project_code rows that need manual attention
                    print(f"WARNING: {blank_count[0]} row(s) have blank project_code. These will need project_code assigned.")
                    print("Adding unique constraint - no duplicates detected among blank project_code rows.")
                    cursor.execute("ALTER TABLE hse_reports ADD UNIQUE KEY uniq_project_month_year (project_code, month, year)")
                    print("Added new constraint 'uniq_project_month_year'")
            else:
                # No rows with blank project_code, safe to add constraint
                cursor.execute("ALTER TABLE hse_reports ADD UNIQUE KEY uniq_project_month_year (project_code, month, year)")
                print("Added new constraint 'uniq_project_month_year'")

        # Migration: Add index for project_code if it doesn't exist
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'hse_reports' 
              AND INDEX_NAME = 'idx_project_code'
        """, (DB_NAME,))
        result = cursor.fetchone()
        if result and result[0] == 0:
            cursor.execute("ALTER TABLE hse_reports ADD INDEX idx_project_code (project_code)")
            print("Added index 'idx_project_code'")

        # Migration: Add composite index for project_code, month, year if it doesn't exist
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'hse_reports' 
              AND INDEX_NAME = 'idx_project_month_year'
        """, (DB_NAME,))
        result = cursor.fetchone()
        if result and result[0] == 0:
            cursor.execute("ALTER TABLE hse_reports ADD INDEX idx_project_month_year (project_code, month, year)")
            print("Added index 'idx_project_month_year'")

        # Migration: Drop unique constraint on report_number if it exists (allow same report_number for different projects)
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM information_schema.TABLE_CONSTRAINTS
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'hse_reports' 
              AND CONSTRAINT_NAME = 'report_number'
        """, (DB_NAME,))
        result = cursor.fetchone()
        if result and result[0] > 0:
            cursor.execute("ALTER TABLE hse_reports DROP INDEX report_number")
            print("Dropped unique constraint on 'report_number'")

        conn.commit()


# ---------------------------------------------------------------------------
# Seed Data Helpers
# ---------------------------------------------------------------------------

def seed_default_users():
    """
    Seed default users:
    - 1 admin
    - 2 Safety Officers
    - 2 Project Managers

    Default password for all users is ADMIN_PASSWORD (env) or 'Simon@54321'.
    """
    password_plain = ADMIN_PASSWORD or "Simon@54321"
    password_hash = generate_password_hash(password_plain, method="pbkdf2:sha256")

    default_users = [
        # Admin
        {
            "username": "admin",
            "email": ADMIN_EMAIL,
            "role": "admin",
            "full_name": "System Administrator",
            "designation": "Administrator",
        }
    ]

    with get_db_connection() as conn:
        cursor = conn.cursor()

        for user in default_users:
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, role, full_name, designation)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    full_name = VALUES(full_name),
                    designation = VALUES(designation),
                    role = VALUES(role)
                """,
                (
                    user["username"],
                    user["email"],
                    password_hash,
                    user["role"],
                    user["full_name"],
                    user["designation"],
                ),
            )

        conn.commit()


def seed_admin_config():
    """
    Seed initial admin configuration:
    - prepared_by_1..3 (type 'prepared_by') with JSON {name, designation}
    - approved_by_1..2 (type 'approved_by') with JSON {name, designation}
    - contractor_1..11 (type 'contractor') with contractor names

    Examples:
    - prepared_by_1: {"name": "Rajesh Kumar", "designation": "Senior Safety Officer"}
    - approved_by_1: {"name": "Biswa Ranjan Dash", "designation": "Project Manager"}
    """
    prepared_by_profiles = [
        {"name": "Rajesh Kumar", "designation": "Senior Safety Officer"},
        {"name": "Priya Sharma", "designation": "Safety Officer"},
        {"name": "Another Safety Officer", "designation": "Safety Officer"},
    ]

    approved_by_profiles = [
        {"name": "Biswa Ranjan Dash", "designation": "Project Manager"},
        {"name": "Anupam Naik", "designation": "Lead - Civil"},
    ]

    contractors = [
        "RRPL",
    ]

    # Default works (Name of Work) – admins can extend/modify from the dashboard
    work_names = [
        "General Construction Work",
    ]

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Insert prepared_by profiles
        for idx, profile in enumerate(prepared_by_profiles, start=1):
            config_key = f"prepared_by_{idx}"
            cursor.execute(
                """
                INSERT INTO admin_config (config_key, config_value, config_type, description)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    config_value = VALUES(config_value),
                    config_type = VALUES(config_type),
                    description = VALUES(description)
                """,
                (
                    config_key,
                    json.dumps(profile),
                    "prepared_by",
                    "Prepared by profile for HSE form dropdown",
                ),
            )

        # Insert approved_by profiles
        for idx, profile in enumerate(approved_by_profiles, start=1):
            config_key = f"approved_by_{idx}"
            cursor.execute(
                """
                INSERT INTO admin_config (config_key, config_value, config_type, description)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    config_value = VALUES(config_value),
                    config_type = VALUES(config_type),
                    description = VALUES(description)
                """,
                (
                    config_key,
                    json.dumps(profile),
                    "approved_by",
                    "Approved by profile for HSE form dropdown",
                ),
            )

        # Insert contractor names
        for idx, contractor in enumerate(contractors, start=1):
            config_key = f"contractor_{idx}"
            cursor.execute(
                """
                INSERT INTO admin_config (config_key, config_value, config_type, description)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    config_value = VALUES(config_value),
                    config_type = VALUES(config_type),
                    description = VALUES(description)
                """,
                (
                    config_key,
                    contractor,
                    "contractor",
                    "Contractor name for HSE form dropdown",
                ),
            )

        # Insert default Name of Work entries
        for idx, work in enumerate(work_names, start=1):
            config_key = f"name_of_work_{idx}"
            cursor.execute(
                """
                INSERT INTO admin_config (config_key, config_value, config_type, description)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    config_value = VALUES(config_value),
                    config_type = VALUES(config_type),
                    description = VALUES(description)
                """,
                (
                    config_key,
                    work,
                    "name_of_work",
                    "Name of work for HSE form dropdown",
                ),
            )

        conn.commit()


# ---------------------------------------------------------------------------
# Cumulative Calculation Logic
# ---------------------------------------------------------------------------

def calculate_cumulative_values(current_data: dict, previous_report_data: dict | None) -> dict:
    """
    Calculate cumulative values for all HSE parameters.

    - Numeric keys (listed in numeric_keys) have their cumulative value computed as:
      previous_cumulative + current.
    - Yes/No style keys (listed in yes_no_keys) simply copy the current-period value
      into the cumulative field.

    - current_data: JSON-like dict for current period, same structure as report_data.
    - previous_report_data: JSON-like dict from last approved report's report_data,
      or None if no previous report exists.
    """
    # Keys 1-26 (numeric) - excluding staff_workmen which should not accumulate
    numeric_keys = [
        "safe_manhours",
        "induction",
        "hse_meetings",
        "hse_awareness",
        "toolbox_talks",
        "fatalities",
        "other_lti",
        "non_disabling",
        "first_aid",
        "near_miss",
        "dangerous_occurrences",
        "unsafe_acts",
        "disciplinary_actions",
        "mandays_lost",
        "lti_free",
        "frequency_rate",
        "severity_rate",
        "jsa_hira",
        "incentives",
        "penalty",
        "audits",
        "pending_ncs",
        "compensation_raised",
        "compensation_resolved",
        "vehicular_accidents",
        "fire_explosion",
    ]

    # Keys that should not accumulate (cumulative = current)
    # staff_workmen: Average number of Staff & Workmen should not be cumulative
    non_cumulative_numeric_keys = [
        "staff_workmen",
    ]

    # Keys 27-32 (Yes/No style flags)
    yes_no_keys = [
        "workmen_compensation",
        "compensation_valid",
        "esi_registered",
        "hirac_register",
        "environment_register",
        "legal_register",
    ]

    result = {}
    prev = previous_report_data or {}

    # Numeric keys: add previous cumulative to current
    for key in numeric_keys:
        current_obj = current_data.get(key, {})
        prev_obj = prev.get(key, {})

        current_val = current_obj.get("current", 0)
        prev_cum = prev_obj.get("cumulative", 0)

        try:
            # Handle both int and float values
            new_cumulative = float(prev_cum) + float(current_val)
        except (TypeError, ValueError):
            new_cumulative = current_val or 0

        result[key] = {
            "current": current_val,
            "cumulative": new_cumulative,
        }

    # Non-cumulative numeric keys: cumulative = current (no accumulation)
    for key in non_cumulative_numeric_keys:
        current_obj = current_data.get(key, {})
        current_val = current_obj.get("current", 0)

        result[key] = {
            "current": current_val,
            "cumulative": current_val,  # Cumulative equals current (no accumulation)
        }

    # Yes/No keys: cumulative = current
    for key in yes_no_keys:
        current_obj = current_data.get(key, {})
        current_val = current_obj.get("current", "No")

        result[key] = {
            "current": current_val,
            "cumulative": current_val,
        }

    return result


# ---------------------------------------------------------------------------
# Initialization Orchestrator
# ---------------------------------------------------------------------------

def init_database():
    """
    Full initialization routine:
    1. Create database if it does not exist.
    2. Create connection pool.
    3. Create core tables.
    4. Seed default users and admin configuration.

    Troubleshooting tips:
    - Verify MySQL is running and credentials in .env are correct.
    - Ensure the user has CREATE DATABASE and CREATE TABLE privileges.
    - If connection errors persist, check firewall/port (default 3306).
    """
    # Step 1: Ensure database exists
    create_database_if_not_exists()

    # Step 2: Initialize connection pool
    create_connection_pool(pool_size=10)

    # Step 3: Create tables
    create_tables()

    # Step 4: Seed data
    seed_default_users()
    seed_admin_config()

    print("MySQL HSE database initialized successfully!")
    print(f"Default admin email: {ADMIN_EMAIL}")
    print(f"Default password for all seeded users: {password_display_hint()}")
    print("For security, change these default passwords after first login.")


def password_display_hint() -> str:
    """
    Helper to avoid printing the raw password if it was overridden
    in production via environment variable.
    """
    if ADMIN_PASSWORD and ADMIN_PASSWORD != "Simon@54321":
        return "<value of ADMIN_PASSWORD from .env>"
    return "Simon@54321"


if __name__ == "__main__":
    init_database()


