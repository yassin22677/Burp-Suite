from flask import Flask
from app.views.auth_routes import auth_bp

def create_app():
    app = Flask(__name__)

    # Register blueprints
    app.register_blueprint(auth_bp)

    return app
