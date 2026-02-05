from app import db

class RLLog(db.Model):
    __tablename__ = "rl_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    raw_line = db.Column(db.Text, nullable=False)
