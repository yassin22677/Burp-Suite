import secrets

import bcrypt
import psycopg2
from flask import Blueprint, jsonify, render_template, request, session

from app.services.postgres import get_connection, pg_errors

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _new_api_token() -> str:
    return secrets.token_urlsafe(32)[:128]


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except ValueError:
        return False


@auth_bp.get("/login")
def login_page():
    return render_template("login.html")


@auth_bp.get("/register")
def register_page():
    return render_template("register.html")


@auth_bp.get("/me")
def me():
    """Session user profile for the dashboard (tokens are not exposed here)."""
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Authentication required"}), 401
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT username, COALESCE(api_token, '') FROM users WHERE id = %s",
                    (uid,),
                )
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "User not found"}), 404
                username, tok = row[0], row[1]
                if not tok:
                    tok = _new_api_token()
                    cur.execute(
                        "UPDATE users SET api_token = %s WHERE id = %s",
                        (tok, uid),
                    )
                    conn.commit()
                return jsonify(
                    {
                        "user_id": uid,
                        "username": username,
                    }
                )
    except psycopg2.OperationalError:
        return jsonify({"error": "Database unavailable. Please try again later."}), 503
    except psycopg2.Error as e:
        if getattr(e, "pgcode", None) == "42703":
            return (
                jsonify(
                    {
                        "error": "Database missing users.api_token — run scripts/pg_align_sessions_and_tokens.sql"
                    }
                ),
                503,
            )
        raise


@auth_bp.post("/signup")
@auth_bp.post("/register")
def signup_api():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    if not email:
        return jsonify({"error": "Email is required"}), 400

    pwd_hash = _hash_password(password)
    api_tok = _new_api_token()

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        """
                        INSERT INTO users (username, email, password_hash, api_token)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                        """,
                        (username, email, pwd_hash, api_tok),
                    )
                except pg_errors.UndefinedColumn:
                    conn.rollback()
                    api_tok = None
                    cur.execute(
                        """
                        INSERT INTO users (username, email, password_hash)
                        VALUES (%s, %s, %s)
                        RETURNING id
                        """,
                        (username, email, pwd_hash),
                    )
                row = cur.fetchone()
                user_id = row[0]
    except pg_errors.UniqueViolation:
        return jsonify({"error": "Username or email already exists"}), 409
    except pg_errors.NotNullViolation:
        return jsonify({"error": "A required field was empty or invalid"}), 400
    except psycopg2.OperationalError:
        return jsonify({"error": "Database unavailable. Please try again later."}), 503
    except psycopg2.Error:
        return jsonify({"error": "Registration failed. Please try again."}), 500

    return (
        jsonify(
            {
                "message": "signup success",
                "user_id": user_id,
            }
        ),
        201,
    )


@auth_bp.post("/login")
def login_api():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, password_hash
                    FROM users
                    WHERE username = %s OR email = %s
                    LIMIT 1
                    """,
                    (username, username),
                )
                row = cur.fetchone()
    except psycopg2.OperationalError:
        return jsonify({"error": "Database unavailable. Please try again later."}), 503
    except psycopg2.Error:
        return jsonify({"error": "Login failed. Please try again."}), 500

    if not row:
        return jsonify({"error": "Invalid username or password"}), 401

    user_id, db_username, password_hash = row
    if not _verify_password(password, password_hash):
        return jsonify({"error": "Invalid username or password"}), 401

    api_tok = ""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COALESCE(api_token, '') FROM users WHERE id = %s",
                    (user_id,),
                )
                r2 = cur.fetchone()
                if r2:
                    api_tok = r2[0] or ""
                if not api_tok:
                    api_tok = _new_api_token()
                    cur.execute(
                        "UPDATE users SET api_token = %s WHERE id = %s",
                        (api_tok, user_id),
                    )
                    conn.commit()
    except psycopg2.Error as e:
        if getattr(e, "pgcode", None) == "42703":
            api_tok = ""
        elif isinstance(e, psycopg2.OperationalError):
            return jsonify({"error": "Database unavailable. Please try again later."}), 503
        else:
            raise

    session["user_id"] = user_id
    return (
        jsonify(
            {
                "message": "login success",
                "user_id": user_id,
                "username": db_username,
            }
        ),
        200,
    )


@auth_bp.post("/logout")
def logout_api():
    uid = session.get("user_id")
    if uid:
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE sessions
                        SET ended_at = CURRENT_TIMESTAMP, status = %s
                        WHERE user_id = %s AND status = %s
                        """,
                        ("completed", uid, "active"),
                    )
        except psycopg2.Error:
            pass
    session.clear()
    return jsonify({"message": "logout success"}), 200
