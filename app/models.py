from app.exts import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(64), unique=True, index=True)
    pass