from flask import Flask, render_template
from app.views.main_routes import main
from app.views.reports_routes import reports_bp

def create_app():
    app = Flask(__name__)

    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(reports_bp)

    return app

