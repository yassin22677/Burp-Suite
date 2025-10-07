# app/__init__.py
import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

def create_app(test_config=None):
    """
    Create and configure the Flask application.
    - Registers blueprints from app.views
    - Enables CORS for local testing
    - Sets up basic logging
    """
    app = Flask(__name__, instance_relative_config=False)

    # Basic config (you can extend / load from env or a config file)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET", "dev-secret"),
    )

    if test_config is not None:
        # allow passing a dict for tests
        app.config.update(test_config)

    # Enable CORS (adjust origins for production)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # --- Logging setup ---
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )
    handler.setFormatter(formatter)
    if not app.logger.handlers:
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # --- Register blueprints ---
    try:
        from app.views.main_routes import main as main_bp
        app.register_blueprint(main_bp)
    except Exception as e:
        app.logger.warning("Could not register main_routes blueprint: %s", e)

    try:
        from app.views.config_routes import config_bp
        app.register_blueprint(config_bp)
    except Exception as e:
        app.logger.warning("Could not register config_routes blueprint: %s", e)

    # (Optional) Register other blueprints here
    # try:
    #     from app.views.other import other_bp
    #     app.register_blueprint(other_bp)
    # except Exception as e:
    #     app.logger.warning("Could not register other blueprint: %s", e)

    # --- Simple error handlers ---
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not Found", "message": str(e)}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Server error: %s", e)
        return jsonify({"error": "Server Error", "message": "An internal error occurred."}), 500

    return app
