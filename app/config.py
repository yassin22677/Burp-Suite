import os
from pathlib import Path
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _normalize_psycopg_dsn(url: str) -> str:
    """SQLAlchemy uses postgresql+psycopg2://; psycopg2.connect() needs postgresql://."""
    for prefix in ("postgresql+psycopg2://", "postgres+psycopg2://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


def _safe_dsn_summary(dsn: str) -> str:
    try:
        u = urlparse(dsn)
        db = (u.path or "").lstrip("/") or "(no db name)"
        return f"host={u.hostname or 'localhost'} port={u.port or 5432} database={db} user={u.username or ''}"
    except Exception:
        return "(unparseable DSN)"


class Config:
    _raw_db_url = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:123@localhost:5432/burp_rl"
    )
    PG_DSN = _normalize_psycopg_dsn(_raw_db_url)
    SQLALCHEMY_DATABASE_URI = _raw_db_url
    if not (
        SQLALCHEMY_DATABASE_URI.startswith("postgresql")
        or SQLALCHEMY_DATABASE_URI.startswith("postgres")
    ):
        SQLALCHEMY_DATABASE_URI = PG_DSN

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get(
        "FLASK_SECRET_KEY", "change-me-in-prod"
    )

    # Burp on same machine: accept JSON user_id without api_token (disable in production).
    RL_TRUST_LOOPBACK_USER_ID = os.environ.get(
        "RL_TRUST_LOOPBACK_USER_ID", "true"
    ).lower() in ("1", "true", "yes")
    # Dev convenience: if Burp posts from 127.0.0.1 without token/user, accept and log.
    RL_ALLOW_ANON_LOOPBACK_EVENTS = os.environ.get(
        "RL_ALLOW_ANON_LOOPBACK_EVENTS", "true"
    ).lower() in ("1", "true", "yes")

    @staticmethod
    def dsn_summary() -> str:
        return _safe_dsn_summary(Config.PG_DSN)
