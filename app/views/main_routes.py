from flask import Blueprint, render_template
from app.services.burp_adapter import check_burp_status

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('dashboard.html')

@main.route('/check-burp')
def check_burp():
    status = check_burp_status()
    return f"<h3>Burp Suite Status:</h3><pre>{status}</pre>"

@main.route('/reports')
def reports():
    return render_template('reports.html')
