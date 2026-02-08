# app/models/scan_session.py
from app import db
from sqlalchemy.dialects.postgresql import UUID
from uuid import uuid4

class ScanSession(db.Model):
    __tablename__ = "scan_sessions"

    # ✅ MUST match your existing Postgres schema (uuid)
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid4)

    website_id = db.Column(db.Integer, db.ForeignKey("websites.id"), nullable=False)

    scan_mode = db.Column(db.String(50))   # passive / active / hybrid
    status = db.Column(db.String(30))      # running / finished

    started_at = db.Column(db.DateTime, server_default=db.func.now())
    ended_at = db.Column(db.DateTime)

    # ✅ now this relationship will work because RLEvent has scan_session_id FK
    rl_events = db.relationship("RLEvent", back_populates="session", lazy=True, cascade="all, delete-orphan")
