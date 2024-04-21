import requests
from requests.auth import HTTPBasicAuth
import json
BASE = "http://127.0.0.1:5000"

class Client:
    username:str
    password:str
    token:str
    auth:HTTPBasicAuth
    
    def __init__(self, username:str, password:str) -> None:
        self.username = username
        self.password = password
        self.token = self.getToken(self.username, self.password)
        self.auth = HTTPBasicAuth(self.token,"")

    # auth
    @staticmethod
    def getToken(username:str, password:str) -> str:
        url = BASE+"/auth/token"
        r = requests.get(url, auth=(username, password))
        assert r.status_code == 200, r
        return r.json()["token"]
        
    @staticmethod        
    def createAccount(username:str, password:str) -> str:
        url = BASE+"/auth/register"
        headers = {"Content-Type":"application/json"}
        data = {"username":username, "password":password}
        r = requests.post(url, headers=headers, data=json.dumps(data))
        assert r.status_code == 201, r
        return r.json()["account-username"]
    
    # game
    def getGames(self) -> dict:
        url = BASE+"/games/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def getLobbies(self) -> dict:
        url = BASE+"/lobby/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def createLobby(self, gameId:int|None=None, gameName:str|None=None) -> int:
        url = BASE+"/lobby/create"
        headers = {"Content-Type":"application/json"}
        data = {}
        if gameId:
            data["game-id"] = gameId
        elif gameName:
            data["game-name"] = gameName
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201
        return r.json()["lobby-id"]
    
    def joinLobby(self, lobbyId:int) -> int:
        url = BASE+"/lobby/join"
        headers = {"Content-Type":"application/json"}
        data = {"lobby-id":lobbyId}
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201
        return r.json()["lobby-id"]

if __name__ == "__main__":
    from pprint import pprint
    username = "frog"
    password = "hat"
    c = Client(username, password)
    lobbyId = c.createLobby(gameName="GuessWho")
    print(c.joinLobby(lobbyId))