from flask_login import UserMixin

from . import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100))
    avatar = db.Column(db.String(100))
