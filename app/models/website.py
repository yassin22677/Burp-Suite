from app import db

class Website(db.Model):
    __tablename__ = "websites"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    base_url = db.Column(db.String(255), nullable=False)
    environment = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    scan_sessions = db.relationship("ScanSession", backref="website", lazy=True, cascade="all, delete-orphan")
