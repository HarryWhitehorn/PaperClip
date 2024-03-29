from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_required, current_user
import json
from . import db, Statement

main = Blueprint("main", __name__)

# Index
@main.route("/")
def index():
    return render_template("index.html")

# Current User Profile
@main.route("/profile")
@login_required
def profile():
    return render_template("profile.html", name=current_user.name)

# Errors
@main.route("/error")
def error():
    # TODO: implement errors fully
    errorCode = "404"
    errorMessage = "Not Found: Requested file was not found"
    return render_template("error.html", errorCode=errorCode, errorMessage=errorMessage, danger=True)

@main.route("/lobby/<int:lobbyId>")
def match(lobbyId):
    data = _JsonLobby(lobbyId)
    return data

@main.route("/lobby/create/<int:gameId>")
def createLobby(gameId, userId=None):
    lobby = Statement.createLobby(gameId, userId)
    data = _JsonLobby(lobby.id)
    return data

@main.route("/lobby/join/<int:lobbyId>")
def joinLobby(lobbyId, userId=None):
    lobby = Statement.joinLobby(lobbyId, userId)
    data = _JsonLobby(lobby.id)
    return data

@main.route("/lobby/find/<int:gameId>")
def findLobby(gameId):
    lobbies = Statement.findLobbies(gameId)
    return [_JsonLobby(lobby.id) for lobby in lobbies]

@main.route("/sandbox")
def sandbox():
    print("snad")
    return "snad"

def _JsonLobby(lobbyId):
    return {"lobby":f"{Statement.getLobby(lobbyId)}", "members":f"{Statement.getMembers(lobbyId)}"}