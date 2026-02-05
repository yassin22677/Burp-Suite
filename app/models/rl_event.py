# app/models/rl_event.py

from datetime import datetime
from app.models import db


class RLEvent(db.Model):
    __tablename__ = "rl_event"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    event_type = db.Column(db.String(20), nullable=False)

    # 🔒 canonical log line from Burp (EXACT)
    raw_line = db.Column(db.Text, nullable=False)
