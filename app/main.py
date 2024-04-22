<<<<<<< Updated upstream
from flask import Blueprint, redirect, render_template, request, url_for, abort, jsonify, g
from flask_httpauth import HTTPBasicAuth
from . import Statement

main = Blueprint("main", __name__)
auth = HTTPBasicAuth()
=======
<<<<<<< Updated upstream
from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_required, current_user
import json
from . import db, Statement

main = Blueprint("main", __name__)
=======
from flask import Blueprint, redirect, render_template, request, url_for, abort, jsonify, g
from flask_httpauth import HTTPBasicAuth
from . import Statement
from .lobbies import LobbyHandler
import udp.auth
import base64

main = Blueprint("main", __name__)
auth = HTTPBasicAuth()
rsaKey = udp.auth.generateRsaKey()
lobbyHandler = LobbyHandler(rsaKey=rsaKey)
>>>>>>> Stashed changes

@auth.verify_password
def verifyPassword(username, password):
    account = Statement.validateToken(username) # check token
    if not account: # if token not valid
        account = Statement.findAccount(username=username) # check account
        if not account or not account.verifyPassword(password): # if account not exist or wrong password
            return False
    g.account = account
    return True
<<<<<<< Updated upstream
=======
>>>>>>> Stashed changes
>>>>>>> Stashed changes

# Index
@main.route("/")
def index():
    return jsonify({})

# auth
@main.route("/auth/register", methods=["POST"])
def createAccount():
    username = request.json.get("username")
    password = request.json.get("password")
    if not (username or password): # check not null
        abort(400) # missing args
    if Statement.findAccount(username): # check if account exists
        abort(400) # account already exists
    account = Statement.createAccount(username, password)
    return jsonify({"account-id":account.id, "username":account.username}), 201

<<<<<<< Updated upstream
@main.route("/auth/token")
@auth.login_required
def getAuthToken():
    token = g.account.generateToken()
    return jsonify({"token": token})

@main.route("/auth/test")
@auth.login_required
def authTest():
    return jsonify({"hello":g.account.username})
=======
<<<<<<< Updated upstream
# Errors
@main.route("/error")
def error():
    # TODO: implement errors fully
    errorCode = "404"
    errorMessage = "Not Found: Requested file was not found"
    return render_template("error.html", errorCode=errorCode, errorMessage=errorMessage, danger=True)

<<<<<<< Updated upstream
@main.route("/lobby/<int:lobbyId>")
def match(lobbyId):
    data = _JsonLobby(lobbyId)
    return data
>>>>>>> Stashed changes

# game
@main.route("/games/")
@auth.login_required
def getGames():
    return jsonify({game.id:game.name for game in Statement.getGames()})

@main.route("/lobby/")
@auth.login_required
def getLobbies():
    lobbies = Statement.getLobbies()
    games = {game.id:game.name for game in Statement.getGames()}
    data = lambda lobby: {"game":{"game-id":lobby.game_id, "game-name":games[lobby.game_id]},"size":Statement.getLobbySize(lobby.id),"is-full":Statement.getIsLobbyFree(lobby.id)}
    return jsonify({lobby.id:data(lobby) for lobby in lobbies})

@main.route("/lobby/create", methods=["POST"])
@auth.login_required
def createLobby():
    gameId = request.json.get("game-id")
    gameName = request.json.get("game-name")
    if not (gameId or gameName): # check args
        abort(400) # missing args
    game = None
    if gameId: # check gameId not null
        game = Statement.getGame(gameId)
    if not game: # check gameId null 
        if gameName: # check gameName not null
            game = Statement.findGame(gameName)
    if not game: # check game null
        abort(404) # no game found
    lobbyId = Statement.createLobby(game.id)
    return jsonify({"lobby-id":lobbyId}), 201

<<<<<<< Updated upstream
@main.route("/lobby/join", methods=["POST"])
@auth.login_required
def joinLobby():
    lobbyId = request.json.get("lobby-id")
    if not lobbyId:
        abort(400)
    return jsonify({"lobby-id":Statement.joinLobby(lobbyId, g.account.id)}), 201
=======
@main.route("/sandbox")
def sandbox():
    print("snad")
    return "snad"

def _JsonLobby(lobbyId):
    return {"lobby":f"{Statement.getLobby(lobbyId)}", "members":f"{Statement.getMembers(lobbyId)}"}
=======
=======
@main.route("/auth/token")
@auth.login_required
def getAuthToken():
    return jsonify({"token":g.account.generateToken()})

@main.route("/auth/key")
@auth.login_required
def getKey():
    return jsonify({"key":base64.encodebytes(g.account.private_key).decode(),"account-id":g.account.id})

@main.route("/auth/certificate")
@auth.login_required
def getCert():
    # return server certificate
    return None

@main.route("/auth/certificate/validate")
def validateCert():
    valid = False
    certificate = request.json.get("certificate")
    certificate = base64.decodebytes(certificate.encode())
    if certificate != None:
        certificate = udp.auth.getCertificateFromDer(certificate)
        attributes = udp.auth.getUserCertificateAttributes(certificate)
        if attributes["account-id"] != None:
            account = Statement.getAccount(attributes["account-id"])
            publicKey = udp.auth.getRsaPublicFromDer(account.public_key)
        else:
            publicKey = rsaKey.public_key()
        valid = udp.auth.validateCertificate(certificate, publicKey)
        return jsonify({"valid":valid})
    else:
        abort(400) # missing args

@main.route("/auth/test")
@auth.login_required
def authTest():
    return jsonify({"hello":g.account.username})

# game
@main.route("/games/")
@auth.login_required
def getGames():
    return jsonify({game.id:game.name for game in Statement.getGames()})

@main.route("/lobby/all")
@auth.login_required
def getLobbies():
    lobbies = LobbyHandler.getAll()
    games = {game.id:game.name for game in Statement.getGames()}
    data = lambda lobby: {"game":{"game-id":lobby.game_id, "game-name":games[lobby.game_id]},"size":Statement.getLobbySize(lobby.id),"is-full":Statement.getIsLobbyFree(lobby.id)}
    return jsonify({lobby.id:data(lobby) for lobby in lobbies})

@main.route("/lobby/create", methods=["POST"])
@auth.login_required
def createLobby():
    gameId = request.json.get("game-id")
    gameName = request.json.get("game-name")
    if not (gameId or gameName): # check args
        abort(400) # missing args
    game = None
    if gameId: # check gameId not null
        game = Statement.getGame(gameId)
    if not game: # check gameId null 
        if gameName: # check gameName not null
            game = Statement.findGame(gameName)
    if not game: # check game null
        abort(404) # no game found
    addr = _getAddr()
    lobby = lobbyHandler.createLobby(addr, game.id)
    return jsonify({"lobby-id":lobby.id,"lobby-addr":lobby.getAddr(), "game-id":lobby.gameId}), 201

def _getAddr():
    host, port = request.host.split(":")
    port = int(port)
    return (host, port)
    
@main.route("/lobby/")
@auth.login_required
def getLobby():
    lobbyId = request.json.get("lobby-id")
    if not lobbyId:
        abort(400) # missing args
    lobby = lobbyHandler.getLobby(lobbyId)
    return jsonify({"lobby-id":lobby.id,"lobby-addr":lobby.getAddr(), "game-id":lobby.gameId})

@main.route("/lobby/members")
@auth.login_required
def getMembers():
    return jsonify(lobbyHandler.getMembers)

@main.route("/lobby/find")
@auth.login_required
def findLobby():
    gameId = request.json.get("game-id")
    gameName = request.json.get("game-name")
    if not (gameId or gameName): # check args
        abort(400) # missing args
    game = None
    if gameId: # check gameId not null
        game = Statement.getGame(gameId)
    if not game: # check gameId null 
        if gameName: # check gameName not null
            game = Statement.findGame(gameName)
    if not game: # check game null
        abort(404) # no game found
    lobby = lobbyHandler.findLobbies(game.id)
    lobby = lobby[0] if len(lobby) > 0 else None
    if lobby != None:
        return jsonify({"lobby-id":lobby.id,"lobby-addr":lobby.getAddr(), "game-id":lobby.gameId})
    else:
        abort(404)
        
@main.route("/friends/")
@auth.login_required
def getFriends():
    friends = Statement.getFriends(g.account.id)
    return jsonify({"friends":[{"id":account.id,"username":account.username} for account in friends]})
    
@main.route("/friends/add", methods=["POST"])
@auth.login_required
def addFriend():
    username = request.json.get("username")
    if username == None:
        abort(400) # missing args
    account = g.account
    other = Statement.findAccount(username)
    if other == None:
        abort(404)
    friends = Statement.createFriends(account.id, other.id)
    return jsonify({"account":{"id":account.id,"username":account.username}, "other":{"id":other.id,"username":other.username}}), 201

@main.route("/lobby/friends")
@auth.login_required
def getFriendLobbies():
    friends = Statement.getFriends(g.account)
    # lobbies = Statement.findLobby()
    
>>>>>>> Stashed changes
>>>>>>> Stashed changes
>>>>>>> Stashed changes
