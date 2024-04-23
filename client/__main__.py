from rps.client import Client as RpsClient
import udp.auth
import base64
import json
import requests
from requests.auth import HTTPBasicAuth
import time

from udp import bcolors

from . import TCP_HOST, TCP_PORT, C_PORT, SERVER_URL

class Client:
    id: int
    username: str
    password: str
    gameClient: None
    token: str
    key: udp.auth.rsa.RSAPublicKey
    auth: HTTPBasicAuth
    
    def __init__(self, username:str, password:str, token:None=None) -> None:
        self.username = username
        self.password = password
        self.gameClient = None
        self.token = token if token != None else self.getToken(self.username, self.password)
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
    
    # friends
    def friendLobbies(self) -> dict:
        url = SERVER_URL+"/lobby/friends"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def getFriends(self) -> dict:
        url = SERVER_URL+"/friends/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()
    
    def addFriend(self, username:str) -> dict:
        url = SERVER_URL+"/friends/add"
        headers = {"Content-Type":"application/json"}
        data = {"username":username}
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201, r
        return r.json()
    
    def removeFriend(self, username:str) -> bool:
        url = SERVER_URL+"/friend/remove"
        headers = {"Content-Type":"application/json"}
        data = {"username":username}
        r = requests.delete(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 204, r
        return True
    
    # join
    def join(self, lobbyId:int):
        print(f"\n{bcolors.WARNING}Joining Lobby '{lobbyId}'{bcolors.ENDC}")
        data = self.getLobby(lobbyId)
        if data["lobby-addr"] != None:
            match data["game-id"]:
                case 1:
                    self.gameClient = RpsClient((TCP_HOST,C_PORT), data["lobby-addr"], rsaKey=self.key, userId=self.id, username=self.username)
                    self.gameClient.connect()
                case _:
                    raise ValueError(f"Unknown gameId {data['game-id']}")

def mainloop():
    print(f"{bcolors.HEADER}\nLobby.{bcolors.ENDC}")
    print("1. Login\n2. Register\n3. Quit")
    while True:
        option = input(": ").strip()
        match option:
            case "1":
                _login()
                break
            case "2":
                _register()
                break
            case "3":
                break
            case _:
                print(f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}")

def _register(username:str|None=None, password:str|None=None):
    print(f"{bcolors.HEADER}\nRegister.{bcolors.ENDC}")
    account = None
    while account == None:
        while username == None or password == None:
            try:
                username = input("Username: ").strip()
                password = input("Password: ").strip()
            except:
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
        try:
            account = Client.createAccount(username, password)
        except AssertionError:
            print(f"{bcolors.FAIL}Account could not be created. Please try again.{bcolors.ENDC}\n")
            username = None
            password = None
    else:
        print(f"Account Created for '{account}'")
        _login(username, password)
        
def _login(username:str|None=None, password:str|None=None):
    print(f"{bcolors.HEADER}\nLogin.{bcolors.ENDC}")
    token = None
    while token == None:
        while username == None or password == None:
            try:
                username = input("Username: ").strip()
                password = input("Password: ").strip()
            except:
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
        try:
            token = Client.getToken(username, password)
        except AssertionError:
            print(f"{bcolors.FAIL}Invalid login details. Please try again.{bcolors.ENDC}\n")
            username = None
            password = None
    else:
        client = Client(username, password, token)
        _menu(client)
    
def _menu(client):
    isRunning = True
    while isRunning:
        print(f"\n{bcolors.HEADER}Main Menu{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}Hello {client.username}.{bcolors.ENDC}")
        while True:
            print("\n1. Manage friends\n2. See available games\n3. Start or join a lobby\n4. Quit")
            option = input(": ").strip()
            match option:
                case "1":
                    _friends(client)
                    break
                case "2":
                    _game(client)
                    break
                case "3":
                    _lobby(client)
                    break
                case "4":
                    isRunning = False
                    break
                case _:
                    print(f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}")
                
def _friends(client:Client):
    while True:
        print(f"{bcolors.HEADER}\nFriends.{bcolors.ENDC}")
        friends = client.getFriends()
        friends = "\n\t".join([f"{i+1}. {friend['username']}" for i,friend in enumerate(friends["friends"])])
        print(f"Friend list: \n\t{friends}")
        # print("\nInput a Username to add new friend, remove a friend or leave blank to return to Main Menu")
        print("\n1. Add New Friend\n2. Remove Friend\n3. Return to Main Menu")
        while True:
            option = input(": ").strip()
            match option:
                case "1"|"2":
                    username = input("\nUsername: ").strip()
                    match option:
                        case "1":
                            try:
                                client.addFriend(username)
                                print(f"\n{bcolors.OKGREEN}Account '{username}' added as friend{bcolors.ENDC}")
                                break
                            except AssertionError:
                                print(f"\n{bcolors.FAIL}Error: No such account with username '{username}'.{bcolors.ENDC}")
                        case "2":
                            try:
                                client.removeFriend(username)
                                print(f"\n{bcolors.OKGREEN}Account '{username}' removed as friend{bcolors.ENDC}")
                                break
                            except AssertionError:
                                print(f"\n{bcolors.FAIL}Error: No such account with username '{username}' in friend list.{bcolors.ENDC}")
                case "3":
                    return None
                case _:
                    print(f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}")
       
                
def _game(client:Client):
    while True:
        print(f"{bcolors.HEADER}\nGames{bcolors.ENDC}")
        availableGames = client.getGames()
        availableGames = "\n\t".join([f"{id}. {game}" for id,game in availableGames.items()])
        print(f"Available Games: \n\t{availableGames}")
        input("\nPress enter to return to main menu: ")
        return None
    
def _lobby(client:Client):
    while True:
        print(f"{bcolors.HEADER}\nLobby.{bcolors.ENDC}")
        print("\n1. Matchmaking\n2. See Friends' Lobbies\n3. Join Lobby\n4. Create Lobby\n5. Return to Main Menu")
        while True:
            option = input(": ").strip()
            match option:
                case "1":
                    _matchmaking(client)
                    break
                case "2":
                    _friendsLobbies(client)
                    break
                case "3":
                    _joinLobby(client)
                    break
                case "4":
                    _createLobby(client)
                    break
                case "5":
                    return None
                case _:
                    print(f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}")
        

def _matchmaking(client:Client):
    print(f"{bcolors.HEADER}\nMatchmaking.{bcolors.ENDC}")
    game = _gameInput(client)
    if game == None:
        return None
    try:
        l = client.findLobby(gameName=game)
    except AssertionError:
        l = client.createLobby(gameName=game)
    time.sleep(1)
    client.join(l["lobby-id"])
    return None

def _friendsLobbies(client:Client):
    print(f"{bcolors.HEADER}\nFriends' Lobbies.{bcolors.ENDC}")
    lobbies = client.friendLobbies()
    lobbiesInfo = lambda lobbies: "\n\t\t".join([f"{bcolors.OKCYAN}{lobby['lobby-id']}{bcolors.ENDC}. {lobby['game-name']}" for lobby in lobbies])
    lobbies = "\n\t".join([f"\n\t{i+1}. {account['account']['username']}:\n\t\t{lobbiesInfo(account['lobbies'])}" for i, account in enumerate(lobbies)])
    print(f"\nLobbies:{lobbies}")
    print(f"Input {bcolors.OKCYAN}Lobby Id{bcolors.ENDC} to Join Friend or Press Enter to Return to Menu.")
    while True:
        option = input(": ").strip()
        if option == "":
            return None
        else:
            try:
                option = int(option)
                client.join(option)
            except ValueError:
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")

def _joinLobby(client:Client):
    print(f"{bcolors.HEADER}\nJoin Lobby.{bcolors.ENDC}")
    lobbyId = None
    while lobbyId == None:
        try:
            lobbyId = input("\nLobby Id: ").strip()
            if lobbyId == "":
                return None
            else:
                lobbyId = int(lobbyId)
        except ValueError:
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
    try:
        client.join(lobbyId)
    except:
        return None

def _createLobby(client:Client):
    print(f"{bcolors.HEADER}\nCreate Lobby.{bcolors.ENDC}")
    game = _gameInput(client)
    while True:
        if game == None:
            return None
        try:
            l = client.createLobby(gameName=game)
            client.join(l["lobby-id"])
            return None
        except AssertionError:
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")

def _gameInput(client:Client) -> str:
    availableGames = client.getGames()
    games = "\n\t".join([f"{id}. {game}" for id,game in availableGames.items()])
    print(f"\nAvailable Games: \n\t{games}")
    game = None
    while game == None or not game.lower() in map(lambda x: x.lower(), availableGames.values()):
        try: 
            game = input("Game: ").strip()
            if game == "":
                return None
        except:
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
    return game
    
    
if __name__ == "__main__":
    # frog hat
    # cat dog
    # fish hook
    from pprint import pprint
    # c = Client("frog","hat")
    # l = c.createLobby(gameName="RPS")
    # c.join(l["lobby-id"])
    mainloop()
