from flask import Flask
from app.models import db
from app.views.rl_event_routes import rl_event_bp

def create_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:123@localhost:5432/burp_rl"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    app.register_blueprint(rl_event_bp)

    return app
