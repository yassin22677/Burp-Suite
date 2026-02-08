from flask import Blueprint, render_template


routes_bp = Blueprint("routes", __name__)

@routes_bp.route("/")
def home():
    return "Burp RL Backend is running"

@routes_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
