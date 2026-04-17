from flask import Flask, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room
from app.config import Config

db = SQLAlchemy()
socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",
    allow_upgrades=False,
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    try:
        import psycopg2

        conn = psycopg2.connect(app.config["PG_DSN"])
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database(), current_schema()")
                dbname, schema = cur.fetchone()
            conn.commit()
            print(f">>> PostgreSQL (psycopg2): database={dbname} schema={schema} <<<")
            print(f">>> {Config.dsn_summary()} <<<")
        finally:
            conn.close()
    except Exception as exc:
        app.logger.warning("PostgreSQL connectivity check failed: %s", exc)

    db.init_app(app)
    socketio.init_app(app)

    @socketio.on("connect")
    def _socketio_connect():
        """Scope live RL log pushes per logged-in user (avoids cross-account leakage)."""
        try:
            uid = session.get("user_id")
            if uid is not None:
                join_room(f"user_{int(uid)}")
        except Exception as exc:
            app.logger.debug("socket connect room join skipped: %s", exc)

    @app.before_request
    def _api_auth_cors_preflight():
        if request.method == "OPTIONS" and (
            request.path.startswith("/auth") or request.path.startswith("/api")
        ):
            return ("", 204)

    @app.after_request
    def _api_auth_cors_headers(response):
        path = request.path
        if not (
            path.startswith("/auth")
            or path.startswith("/api")
            or path.startswith("/logs")
        ):
            return response
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    with app.app_context():
        from app.models.user import User
        from app.models.website import Website
        from app.models.scan_session import ScanSession
        from app.models.rl_event import RLEvent
        from app.models.rl_log import RLLog

        try:
            db.create_all()
        except Exception as exc:
            app.logger.warning("db.create_all() skipped or failed: %s", exc)

    from app.views.routes import routes_bp
    app.register_blueprint(routes_bp)

    from app.views.auth_routes import auth_bp
    app.register_blueprint(auth_bp)

    from app.views.rl_event_routes import rl_event_bp
    app.register_blueprint(rl_event_bp)

    from app.views.scan_session_routes import scan_session_bp
    app.register_blueprint(scan_session_bp)

    from app.views.rl_burp_routes import rl_burp_bp
    app.register_blueprint(rl_burp_bp)

    from app.views.log_routes import log_bp
    app.register_blueprint(log_bp)

    from app.views.proxy_request_routes import proxy_request_bp
    app.register_blueprint(proxy_request_bp)

    return app
