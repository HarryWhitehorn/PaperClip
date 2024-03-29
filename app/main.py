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

@main.route("/lobby", methods="POST")
def viewLobby():
    if request.method == "POST":
        lobbyId = request.form["lobby"]
        data = _JsonLobby(lobbyId)
        return data
    return {}

@main.route("/lobby/create", methods="POST")
def createLobby():
    if request.method == "POST":
        gameId = request.form["game"]
        userId = request.form.get("user")
        lobby = Statement.createLobby(gameId, userId)
        data = _JsonLobby(lobby.id)
        return data
    return {}

@main.route("/lobby/join", methods="POST")
def joinLobby():
    if request.method == "POST":
        lobbyId = request.form["lobby"]
        userId = request.form.get("user")
        lobby = Statement.joinLobby(lobbyId, userId)
        data = _JsonLobby(lobby.id)
        return data
    return {}

@main.route("/lobby/find", methods="POST")
def findLobby():
    if request.method == "POST":
        gameId = request.form["game"]
        lobbies = Statement.findLobbies(gameId)
        return [_JsonLobby(lobby.id) for lobby in lobbies]
    return {}

@main.route("/sandbox")
def sandbox():
    print("snad")
    return "snad"

def _JsonLobby(lobbyId):
    return {"lobby":f"{Statement.getLobby(lobbyId)}", "members":f"{Statement.getMembers(lobbyId)}"}