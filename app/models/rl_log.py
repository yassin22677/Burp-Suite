from app import db


class RLLog(db.Model):
    """rl_logs — session_id is FK to sessions.id (integer), nullable."""

    __tablename__ = "rl_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    raw_line = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(
        db.Integer, db.ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    target_host = db.Column(db.Text, nullable=True)
    event_type = db.Column(db.Text, nullable=True)
