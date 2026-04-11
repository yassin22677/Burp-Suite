"""Direct PostgreSQL access via psycopg2 for auth and scan sessions."""

from contextlib import contextmanager

import psycopg2
from flask import current_app
from psycopg2 import errors as pg_errors

__all__ = ["get_connection", "pg_errors"]


@contextmanager
def get_connection():
    """Open a connection, commit on success, rollback on error, always close."""
    dsn = current_app.config["PG_DSN"]
    conn = psycopg2.connect(dsn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
