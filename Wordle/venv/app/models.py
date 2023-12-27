from . import db
from flask_login import UserMixin




class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(80), nullable = False)
    secure_question = db.Column(db.String(80), nullable = True)
    secure_answer = db.Column(db.String(80), nullable = False)
    e_mail = db.Column(db.String(80), nullable = True)
    is_user_admin = db.Column(db.Boolean, default=False, nullable = False)


class Game(db.Model):
    id_game = db.Column(db.Integer, primary_key=True)
    id_Host = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    id_Join = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    winner = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    host = db.relationship('User', foreign_keys=[id_Host], backref=db.backref('hosted_games', lazy=True))
    joiner = db.relationship('User', foreign_keys=[id_Join], backref=db.backref('joined_games', lazy=True))
    winner_user = db.relationship('User', foreign_keys=[winner], backref=db.backref('won_games', lazy=True))

class Gamewords(db.Model):
    id_word = db.Column(db.Integer, primary_key = True)
    words = db.Column(db.String)

