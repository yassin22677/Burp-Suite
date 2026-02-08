from app import db
from sqlalchemy.dialects.postgresql import UUID

class RLEvent(db.Model):
    __tablename__ = "rl_events"  # make sure this matches your real table name

    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(UUID(as_uuid=True), db.ForeignKey("scan_sessions.id"), nullable=False)

    raw_line = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    session = db.relationship("ScanSession", back_populates="rl_events")
