from flask import Blueprint, redirect, render_template, request, url_for, abort, jsonify, g
from flask_httpauth import HTTPBasicAuth
from . import Statement

main = Blueprint("main", __name__)
auth = HTTPBasicAuth()

@auth.verify_password
def verifyPassword(username, password):
    account = Statement.validateToken(username) # check token
    if not account: # if token not valid
        account = Statement.findAccount(username=username) # check account
        if not account or not account.verifyPassword(password): # if account not exist or wrong password
            return False
    g.account = account
    return True

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

@main.route("/auth/token")
@auth.login_required
def getAuthToken():
    token = g.account.generateToken()
    return jsonify({"token": token})

@main.route("/auth/test")
@auth.login_required
def authTest():
    return jsonify({"hello":g.account.username})

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

@main.route("/lobby/join", methods=["POST"])
@auth.login_required
def joinLobby():
    lobbyId = request.json.get("lobby-id")
    if not lobbyId:
        abort(400)
    return jsonify({"lobby-id":Statement.joinLobby(lobbyId, g.account.id)}), 201