from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from app.config import Config

db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    socketio.init_app(app)

    with app.app_context():
        from app.models.user import User
        from app.models.website import Website
        from app.models.scan_session import ScanSession
        from app.models.rl_event import RLEvent
        from app.models.rl_log import RLLog
        db.create_all()

    from app.views.routes import routes_bp
    app.register_blueprint(routes_bp)

    from app.views.rl_event_routes import rl_event_bp
    app.register_blueprint(rl_event_bp)

    from app.views.scan_session_routes import scan_session_bp
    app.register_blueprint(scan_session_bp)

    return app
