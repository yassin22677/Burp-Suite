from flask import Blueprint, render_template

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
def reports():
    vulnerabilities = [
        {"id": 1, "severity": "Critical", "name": "Command Injection", "endpoint": "/upload", "status": "Open", "confidence": "95%"},
        {"id": 2, "severity": "High", "name": "SQL Injection", "endpoint": "/login", "status": "Open", "confidence": "92%"},
        {"id": 3, "severity": "Medium", "name": "Cross-Site Scripting (XSS)", "endpoint": "/search", "status": "Resolved", "confidence": "89%"},
        {"id": 4, "severity": "Low", "name": "Information Disclosure", "endpoint": "/about", "status": "Open", "confidence": "76%"},
        {"id": 5, "severity": "High", "name": "Insecure Deserialization", "endpoint": "/api/upload", "status": "Open", "confidence": "90%"}
    ]

  
    return render_template('reports.html', vulns=vulnerabilities)
