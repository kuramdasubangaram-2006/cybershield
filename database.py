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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
