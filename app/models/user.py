import bcrypt
from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    api_token = db.Column(db.String(128), unique=True, nullable=True)

    websites = db.relationship(
        "Website", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    sessions = db.relationship(
        "ScanSession", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except ValueError:
            return False
