from flask import Blueprint, request, jsonify
from app.models.user import User
from app import db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.post("/login")
def login_api():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid email or password"}), 401

    # ✅ NO TOKEN, NO SESSION
    return jsonify({
        "message": "login success",
        "user_id": user.id,
        "email": user.email
    }), 200
