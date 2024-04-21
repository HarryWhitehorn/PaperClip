from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask import current_app
import jwt
import datetime
# from . import db

db = SQLAlchemy()

# # flask login
# class User(UserMixin, db.Model):
#     user_id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(1000))
#     email = db.Column(db.String(100), unique=True)
#     password = db.Column(db.String(100))

#     def get_id(self):
#         return self.user_id

# models
class Friends(db.Model):
    account_one_id = db.Column(db.Integer, db.ForeignKey("account.id"), primary_key=True)
    account_two_id = db.Column(db.Integer, db.ForeignKey("account.id"), primary_key=True)
    

class Scores(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False)


class Members(db.Model):
    lobby_id = db.Column(db.Integer, db.ForeignKey("lobby.id"), primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), primary_key=True)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(162), nullable=False)  # binary type?
    members = db.relationship("Members", backref="account", lazy=True)    
    # friends = db.relationship(
    #     "Account", secondary=friends, backref="account", lazy=True
    # )  # ToDo: check valid relationship?
    # scores = db.relationship(
    #     "Game", secondary=scores, backref="account", lazy=True
    # )
    def hashPassword(self, password:str) -> None:
        self.password = generate_password_hash(password)
        
    def verifyPassword(self, password:str) -> bool:
        return check_password_hash(self.password, password)
    
    def generateToken(self, expiration:int=600) -> str:
        data = {"id":self.id,"exp":datetime.datetime.now()+datetime.timedelta(seconds=expiration)}
        token = jwt.encode(data, current_app.config['SECRET_KEY'], algorithm="HS256")
        return token
    
    @staticmethod
    def validateToken(token:str):
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], leeway=datetime.timedelta(seconds=10), algorithms=["HS256"])
        except:
            return False
        account = Statement.getAccount(data.get("id"))
        return account


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    lobbies = db.relationship("Lobby", backref="game", lazy=True)
    min_players = db.Column(db.Integer, default=1)
    max_players = db.Column(db.Integer)
    # scores = db.relationship("Account", secondary=scores, backref="game", lazy=True)


class Lobby(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False) 
    members = db.relationship("Members", backref="lobby", cascade="all, delete", lazy=True)
    # max_players = db.Column(db.Integer) # to overwrite game max (must be fewer than Game.max_players)


class Statement():
    # get
    @staticmethod
    def getGame(gameId):
        return Game.query.filter_by(id=gameId).scalar()
    
    @staticmethod
    def getGames():
        return Game.query.all()
    
    @staticmethod
    def getLobby(lobbyId):
        return Lobby.query.filter_by(id=lobbyId).scalar()
    
    @staticmethod
    def getLobbies():
        return Lobby.query.all()
    
    @staticmethod
    def getLobbySize(lobbyId):
        return len(Members.query.filter_by(lobby_id=lobbyId).all())
    
    @staticmethod
    def getIsLobbyFree(lobbyId):
        lobby = Statement.getLobby(lobbyId)
        game = Statement.getGame(lobby.game_id)
        return Statement.getLobbySize(lobbyId) < game.max_players
    
    @staticmethod
    def getAccount(userId):
        return Account.query.filter_by(id=userId).scalar()
    
    @staticmethod
    def getMembers(lobbyId):
        return Members.query.filter_by(lobby_id=lobbyId).all()
    
    # create
    @staticmethod
    def createAccount(username:str, password:str) -> Account:
        account = Account(username=username)
        account.hashPassword(password)
        db.session.add(account)
        db.session.commit()
        return account
        
    
    @staticmethod
    def createLobby(gameId,userId=None) -> int:
        lobby = Lobby(game_id=gameId)
        db.session.add(lobby)
        if userId != None:
            account = Statement.getAccount(userId)
            member = Members(lobby_id=lobby.id,account_id=account.id)
            db.session.add(member)
        db.session.commit()
        return lobby.id
    
    # join
    @staticmethod
    def joinLobby(lobbyId, userId):
        lobby = Statement.getLobby(lobbyId)
        if userId != None:
            account = Statement.getAccount(userId)
            member = Members(lobby_id=lobby.id,account_id=account.id)
            db.session.add(member)
        db.session.commit()
        return lobby.id
    
    # find
    @staticmethod
    def findAccount(username) -> Account|None:
        return Account.query.filter_by(username=username).scalar()
    
    @staticmethod
    def validateToken(token) -> Account|None:
        return Account.validateToken(token)
    
    @staticmethod
    def findGame(gameName:str):
        return Game.query.filter_by(name=gameName).scalar()
    
    @staticmethod
    def findLobbies(gameId):
        lobbies = Lobby.query.filter_by(game_id=gameId)
        freeLobbies = [lobby for lobby in lobbies if Statement.getIsLobbyFree(lobby.id)]
        return freeLobbies
    
    # delete
    @staticmethod
    def deleteLobby(lobbyId):
        lobby = Statement.getLobby(lobbyId)
        db.session.delete(lobby)
        db.session.commit()
        return lobbyId