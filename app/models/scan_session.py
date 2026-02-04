from . import db

class ScanSession(db.Model):
    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey("websites.id"), nullable=False)

    scan_mode = db.Column(db.String(50))  # passive / active / hybrid
    status = db.Column(db.String(30))     # running / finished

    started_at = db.Column(db.DateTime, server_default=db.func.now())
    ended_at = db.Column(db.DateTime)

    rl_events = db.relationship("RLEvent", backref="session", lazy=True)
