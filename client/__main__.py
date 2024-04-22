from rps.client import Client as RpsClient
import udp.auth
import base64
import json
import requests
from requests.auth import HTTPBasicAuth

from . import HOST, PORT, C_PORT, SERVER_URL

class Client:
    id: int
    username: str
    password: str
    gameClient: None
    token: str
    key: udp.auth.rsa.RSAPublicKey
    auth: HTTPBasicAuth
    
    def __init__(self, username:str, password:str) -> None:
        self.username = username
        self.password = password
        self.gameClient = None
        self.token = self.getToken(self.username, self.password)
        self.auth = HTTPBasicAuth(self.token,"")
        self.getKey(password.encode())

    # auth
    @staticmethod
    def getToken(username:str, password:str) -> str:
        url = SERVER_URL+"/auth/token"
        r = requests.get(url, auth=(username, password))
        assert r.status_code == 200, r
        return r.json()["token"]
        
    @staticmethod        
    def createAccount(username:str, password:str) -> str:
        url = SERVER_URL+"/auth/register"
        headers = {"Content-Type":"application/json"}
        data = {"username":username, "password":password}
        r = requests.post(url, headers=headers, data=json.dumps(data))
        assert r.status_code == 201, r
        return r.json()["username"]
    
    def getKey(self, password:bytes):
        url = SERVER_URL+"/auth/key"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        self.id = r.json()["account-id"]
        key = base64.decodebytes(r.json()["key"].encode())
        self.key = udp.auth.getRsaPrivateFromDer(key, password)
    
    # game
    def getGames(self) -> dict:
        url = SERVER_URL+"/games/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def getLobbies(self) -> dict:
        url = SERVER_URL+"/lobby/all"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def createLobby(self, gameId:int|None=None, gameName:str|None=None) -> dict:
        url = SERVER_URL+"/lobby/create"
        headers = {"Content-Type":"application/json"}
        data = {}
        if gameId:
            data["game-id"] = gameId
        elif gameName:
            data["game-name"] = gameName
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201, r
        return r.json()
    
    def getLobby(self, lobbyId:int) -> dict:
        url = SERVER_URL+"/lobby/"
        headers = {"Content-Type":"application/json"}
        data = {"lobby-id":lobbyId}
        r = requests.get(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 200
        return r.json()
    
    def findLobby(self, gameId:int|None=None, gameName:str|None=None) -> dict:
        url = SERVER_URL+"/lobby/find"
        headers = {"Content-Type":"application/json"}
        data = {}
        if gameId:
            data["game-id"] = gameId
        elif gameName:
            data["game-name"] = gameName
        r = requests.get(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def getFriends(self) -> dict:
        url = SERVER_URL+"/friends/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def addFriend(self, username):
        url = SERVER_URL+"/friends/add"
        headers = {"Content-Type":"application/json"}
        data = {"username":username}
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201, r
        return r.json()
    
    def join(self, lobbyId:int):
        data = self.getLobby(lobbyId)
        if data["lobby-addr"] != None:
            match data["game-id"]:
                case 1:
                    self.gameClient = RpsClient((HOST,C_PORT), data["lobby-addr"], rsaKey=self.key, userId=self.id, username=self.username)
                    self.gameClient.connect()
                case _:
                    raise ValueError(f"Unknown gameId {data['game-id']}")

if __name__ == "__main__":
    from pprint import pprint
    username = "frog"
    password = "hat"
    other = ("cat", "dog")
    # Client.createAccount(username, password)
    # Client.createAccount(*other)
    c = Client(username, password)
    l = c.createLobby(gameName="RPS")
    # l = c.findLobby(gameName="RPS")
    # f = c.addFriend("cat")
    f = c.getFriends()
    pprint(f)
    c.join(l["lobby-id"])
