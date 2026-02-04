from . import db

class XAIExplanation(db.Model):
    __tablename__ = "xai_explanations"

    id = db.Column(db.Integer, primary_key=True)
    rl_event_id = db.Column(db.Integer, db.ForeignKey("rl_events.id"), nullable=False)

    explanation_text = db.Column(db.Text, nullable=False)
    state_summary = db.Column(db.JSON)
    confidence_score = db.Column(db.Float)
