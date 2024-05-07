import datetime

import jwt
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

import udp.auth as auth

db = SQLAlchemy()


# models
class Friends(db.Model):
    account_one_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )
    account_two_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )


class Scores(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(162), nullable=False)
    private_key = db.Column(db.LargeBinary(1337))
    public_key = db.Column(db.LargeBinary(294))

    def hashPassword(self, password: str) -> None:
        self.password = generate_password_hash(password)

    def verifyPassword(self, password: str) -> bool:
        return check_password_hash(self.password, password)

    def generateToken(self, expiration: int = 600) -> str:
        data = {
            "id": self.id,
            "exp": datetime.datetime.now() + datetime.timedelta(seconds=expiration),
        }
        token = jwt.encode(data, current_app.config["SECRET_KEY"], algorithm="HS256")
        return token

    @staticmethod
    def validateToken(token: str):
        try:
            data = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                leeway=datetime.timedelta(seconds=10),
                algorithms=["HS256"],
            )
        except:  # noqa: E722
            return None
        account = Statement.getAccount(data.get("id"))
        return account

    def generateKey(self, password: bytes) -> None:
        k = auth.generateRsaKey()
        self.private_key = auth.getDerFromRsaPrivate(k, password)
        self.public_key = auth.getDerFromRsaPublic(k.public_key())

    @staticmethod
    def decryptKey(self, key: bytes, password: bytes) -> auth.rsa.RSAPublicKey:
        k = auth.getRsaPrivateFromDer(key, password)
        return k


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    min_players = db.Column(db.Integer, default=1)
    max_players = db.Column(db.Integer)


class Statement:
    # get
    @staticmethod
    def getGame(gameId: int) -> Game:
        return Game.query.filter_by(id=gameId).scalar()

    @staticmethod
    def getGames() -> list[Game]:
        return Game.query.all()

    @staticmethod
    def getAccount(userId: int) -> Account:
        return Account.query.filter_by(id=userId).scalar()

    @staticmethod
    def getFriends(accountId: int) -> list[Account]:
        friends = Friends.query.filter(
            (Friends.account_one_id == accountId)
            | (Friends.account_two_id == accountId)
        )
        friends = [
            friend.account_one_id
            if friend.account_one_id != accountId
            else friend.account_two_id
            for friend in friends
        ]
        friends = [Statement.getAccount(id) for id in friends]
        return friends

    # create
    @staticmethod
    def createAccount(username: str, password: str) -> Account:
        account = Account(username=username)
        account.hashPassword(password)
        account.generateKey(password.encode())
        db.session.add(account)
        db.session.commit()
        return account

    @staticmethod
    def createFriends(accountIdOne: int, accountIdTwo: int) -> Friends:
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends(account_one_id=idOne, account_two_id=idTwo)
        db.session.add(friends)
        db.session.commit()
        return friends
    
    @staticmethod
    def createGame(id:int, name:str, min_players:int, max_players:int) -> Game:
        game = Game(id=id, name=name, min_players=min_players, max_players=max_players)
        db.session.add(game)
        db.session.commit()
        return game

    # find
    @staticmethod
    def findAccount(username: str) -> Account | None:
        return Account.query.filter_by(username=username).scalar()

    @staticmethod
    def validateToken(token: str) -> Account | None:
        return Account.validateToken(token)

    @staticmethod
    def findGame(gameName: str) -> Game | None:
        return Game.query.filter_by(name=gameName).scalar()

    # delete
    @staticmethod
    def removeFriends(accountIdOne: int, accountIdTwo: int) -> bool:
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends.query.filter(
            (Friends.account_one_id == idOne) & (Friends.account_two_id == idTwo)
        )
        if friends is not None:
            friends.delete()
            db.session.commit()
            return True
        else:
            return False
