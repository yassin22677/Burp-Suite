"""Use app.services.postgres.get_connection for psycopg2 access."""

from app.services.postgres import get_connection

__all__ = ["get_connection"]
