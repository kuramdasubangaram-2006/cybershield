"""Database connections for local SQLite and hosted PostgreSQL."""

import sqlite3

from flask import current_app, g

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # PostgreSQL support is optional for local SQLite development.
    psycopg = None
    dict_row = None


INTEGRITY_ERRORS = (
    (sqlite3.IntegrityError, psycopg.IntegrityError)
    if psycopg is not None
    else (sqlite3.IntegrityError,)
)


class PostgresConnection:
    """Keep qmark SQL placeholders working with psycopg."""

    def __init__(self, connection):
        self.connection = connection

    def execute(self, statement, parameters=()):
        return self.connection.execute(statement.replace("?", "%s"), parameters)

    def __getattr__(self, name):
        return getattr(self.connection, name)


def get_db():
    if "db" not in g:
        database_url = current_app.config.get("DATABASE_URL", "").strip()
        if database_url:
            if psycopg is None:
                raise RuntimeError("PostgreSQL support is missing. Install the project requirements first.")
            connection = psycopg.connect(database_url, sslmode="require", row_factory=dict_row)
            g.db = PostgresConnection(connection)
        else:
            g.db = sqlite3.connect(current_app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    # Supabase tables are created separately with supabase_schema.sql.
    if app.config.get("DATABASE_URL"):
        return
    with app.app_context():
        get_db().executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                risk TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                analysis_details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS admin_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_email TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_rate_limits (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                window_start TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, window_start)
            );

            CREATE TABLE IF NOT EXISTS password_reset_codes (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                requested_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS endpoint_agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT,
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS endpoint_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
                source_ref TEXT NOT NULL,
                event_time TEXT NOT NULL,
                channel TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                network_protocol TEXT,
                network_direction TEXT,
                event_name TEXT NOT NULL,
                alert_level TEXT,
                alert_text TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(agent_id, source_ref)
            );

            CREATE INDEX IF NOT EXISTS endpoint_agents_user_idx
                ON endpoint_agents(user_id, revoked_at);
            CREATE INDEX IF NOT EXISTS endpoint_events_agent_created_idx
                ON endpoint_events(agent_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS endpoint_events_failed_login_idx
                ON endpoint_events(agent_id, event_id, source_ip, created_at);
            """
        )
        endpoint_event_columns = {row["name"] for row in get_db().execute("PRAGMA table_info(endpoint_events)").fetchall()}
        for column, sql_type in (
            ("source_port", "INTEGER"),
            ("destination_ip", "TEXT"),
            ("destination_port", "INTEGER"),
            ("network_protocol", "TEXT"),
            ("network_direction", "TEXT"),
        ):
            if column not in endpoint_event_columns:
                get_db().execute(f"ALTER TABLE endpoint_events ADD COLUMN {column} {sql_type}")
        get_db().commit()
        scan_columns = {row["name"] for row in get_db().execute("PRAGMA table_info(scans)").fetchall()}
        if "user_hidden_at" not in scan_columns:
            get_db().execute("ALTER TABLE scans ADD COLUMN user_hidden_at TEXT")
            get_db().commit()
        if "analysis_details" not in scan_columns:
            get_db().execute("ALTER TABLE scans ADD COLUMN analysis_details TEXT NOT NULL DEFAULT '{}'")
            get_db().commit()
