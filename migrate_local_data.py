"""Copy local SQLite accounts and scan history into an empty Supabase database."""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
LOCAL_DATABASE = PROJECT_ROOT / "instance" / "cybershield.sqlite3"


def utc_timestamp(value):
    if isinstance(value, datetime):
        timestamp = value
    else:
        timestamp = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def main():
    load_dotenv(PROJECT_ROOT / ".env")
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise SystemExit("DATABASE_URL is missing from the local .env file. Do not paste database credentials into chat.")
    if not LOCAL_DATABASE.exists():
        raise SystemExit("The local CyberShield database file was not found.")

    try:
        import psycopg
    except ImportError as error:
        raise SystemExit("PostgreSQL support is missing. Install the project requirements first.") from error

    local = sqlite3.connect(LOCAL_DATABASE)
    local.row_factory = sqlite3.Row
    try:
        users = local.execute(
            "SELECT id, email, password_hash, role, created_at FROM users ORDER BY id"
        ).fetchall()
        scans = local.execute(
            "SELECT id, user_id, module, target, risk, summary, created_at FROM scans ORDER BY id"
        ).fetchall()
    finally:
        local.close()

    if not users:
        raise SystemExit("No local accounts were found; migration stopped without changing Supabase.")

    imported_users = 0
    imported_scans = 0
    with psycopg.connect(database_url, sslmode="require") as remote:
        with remote.cursor() as cursor:
            remote_user_count = cursor.execute("SELECT COUNT(*) FROM public.users").fetchone()[0]
            remote_scan_count = cursor.execute("SELECT COUNT(*) FROM public.scans").fetchone()[0]
            if remote_user_count or remote_scan_count:
                raise SystemExit("Supabase tables already contain data; migration stopped without adding records.")

            for user in users:
                cursor.execute(
                    "INSERT INTO public.users (id, email, password_hash, role, created_at) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (user["id"], user["email"], user["password_hash"], user["role"], utc_timestamp(user["created_at"])),
                )
                imported_users += 1

            for scan in scans:
                cursor.execute(
                    "INSERT INTO public.scans (id, user_id, module, target, risk, summary, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        scan["id"], scan["user_id"], scan["module"], scan["target"], scan["risk"],
                        scan["summary"], utc_timestamp(scan["created_at"]),
                    ),
                )
                imported_scans += 1

            cursor.execute(
                "SELECT setval(pg_get_serial_sequence('public.users', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) "
                "FROM public.users"
            )
            cursor.execute(
                "SELECT setval(pg_get_serial_sequence('public.scans', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) "
                "FROM public.scans"
            )

    print(f"Migration complete: {imported_users} accounts and {imported_scans} scan records copied.")
    print("Only password hashes were copied; plain-text passwords were not available or transferred.")


if __name__ == "__main__":
    main()
