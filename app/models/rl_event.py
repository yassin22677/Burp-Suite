from datetime import datetime
from app.models import db

class RLEvent(db.Model):
    __tablename__ = "rl_event"

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # DECIDE / APPLY / RESPONSE / REWARD
    event_type = db.Column(db.String(20), nullable=False)

    request_id = db.Column(db.Integer, nullable=True)

    # ✅ STORE STRING ACTION NAME ONLY
    action_name = db.Column(db.String(100), nullable=True)

    url = db.Column(db.Text, nullable=True)
    http_method = db.Column(db.String(10), nullable=True)

    # RESPONSE / REWARD DATA
    status_code = db.Column(db.Integer, nullable=True)
    reward = db.Column(db.Integer, nullable=True)

    raw_line = db.Column(db.Text, nullable=True)
