from app import db


class RLEvent(db.Model):
    """rl_event — timestamp & event_type are NOT NULL in PostgreSQL."""

    __tablename__ = "rl_event"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    event_type = db.Column(db.String(64), nullable=False)
    request_id = db.Column(db.Integer, nullable=True)
    action_id = db.Column(db.Integer, nullable=True)
    action_name = db.Column(db.String(255), nullable=True)
    url = db.Column(db.Text, nullable=True)
    http_method = db.Column(db.String(32), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    reward = db.Column(db.Integer, nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    raw_line = db.Column(db.Text, nullable=True)
