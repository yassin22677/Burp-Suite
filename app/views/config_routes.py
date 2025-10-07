# app/views/config_routes.py
from flask import Blueprint, render_template, jsonify, request, current_app
import json, os
from app.services.burp_adapter import apply_config_to_burp

config_bp = Blueprint('config', __name__)

# persisted config file in project root (or store in DB)
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'burp_config.json')
os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

default_config = {
    "scanner_threshold":"medium",
    "active_checks": True,
    "passive_checks": True,
    "scan_speed": 5,
    "max_scans": 2,
    "scope": []
}

def read_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
    except Exception as e:
        current_app.logger.error("read_config error: %s", e)
    return default_config.copy()

def write_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception as e:
        current_app.logger.error("write_config error: %s", e)
        return False

# ---- Page route ----
@config_bp.route('/configuration', methods=['GET'])
def configuration_page():
    return render_template('configuration.html')

# ---- API endpoints ----
@config_bp.route('/api/config', methods=['GET'])
def get_config():
    cfg = read_config()
    return jsonify(cfg), 200

@config_bp.route('/api/config', methods=['PUT'])
def save_config():
    data = request.get_json() or {}
    cfg = read_config()
    cfg.update(data)
    ok = write_config(cfg)
    if ok:
        return jsonify({"message":"saved"}), 200
    return ("Failed to save", 500)

@config_bp.route('/api/config/apply', methods=['POST'])
def apply_config():
    data = request.get_json() or {}
    cfg = read_config()
    cfg.update(data)
    write_config(cfg)
    try:
        result = apply_config_to_burp(cfg)
        return jsonify({"message": result}), 200
    except Exception as e:
        current_app.logger.exception("apply_config error")
        return (str(e), 500)
