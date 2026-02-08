from flask import Blueprint, jsonify
from app import db
from app.models.scan_session import ScanSession

scan_session_bp = Blueprint("scan_session", __name__, url_prefix="/api/scan")

@scan_session_bp.post("/start")
def start_scan():
    session = ScanSession(
        website_id=1,        # must exist in DB
        scan_mode="active",
        status="running"
    )

    db.session.add(session)
    db.session.commit()

    return jsonify({
        "scan_session_id": str(session.id)
    }), 201
