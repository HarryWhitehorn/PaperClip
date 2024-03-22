from enum import Enum
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
# from . import db

db = SQLAlchemy()

# meta login
class Users(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def get_id(self):
        return self.user_id

# class Friends(db.Model):
#     pass

friends = db.Table(
    "friends",
    db.Column("account_one_id", db.Integer, db.ForeignKey("account.id"), primary_key=True),
    db.Column("account_two_id", db.Integer, db.ForeignKey("account.id"), primary_key=True),
)

# class Score(db.Model):
#     pass

scores = db.Table(
    "scores",
    db.Column("score", db.Integer, nullable=False),
    db.Column("account_id", db.Integer, db.ForeignKey("account.id"), primary_key=True),
    db.Column("game_id", db.Integer, db.ForeignKey("game.id"), primary_key=True),
)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # binary type?
    friends = db.relationship(
        "Account", secondary=friends, backref="account", lazy=True
    )  # ToDo: check valid relationship?
    scores = db.relationship(
        "Game", secondary=scores, backref="account", lazy=True
    )


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lobbies = db.relationship("Lobby", backref="game", lazy=True)
    scores = db.relationship("Account", secondary=scores, backref="game", lazy=True)


class Lobby(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False)


# class LobbyMembers(db.Model):
#     pass
