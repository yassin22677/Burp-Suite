from app import db


class ScanSession(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    token_type = db.Column(db.String(20), nullable=False)
    token_value = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="active")

    started_at = db.Column(db.DateTime, server_default=db.func.now())
    ended_at = db.Column(db.DateTime)
