<<<<<<< Updated upstream
from threading import Thread

class Lobby:
    members: list[int]
    severThread: Thread
    port: int
    
    def __init__(self, port):
        pass
=======
from threading import Thread, Lock
import datetime
import time

from udp.server import Server
from rps.server import Server as RpsSever

PRUNE_TIME = 26

class Lobby:
    id: int
    members: list[tuple[str, int]]
    addr: int
    gameServer: Server
    severThread: Thread
    gameId: int|None
    heartbeat: bool|datetime.datetime
    
    def __init__(self, id:int, addr, gameId:int|None=None, rsaKey=None):
        self.id = id
        self.members = []
        self.addr = addr
        self.gameId = gameId
        self.heartbeat = datetime.datetime.now()
        match gameId:
            case 1:
                self.gameServer = RpsSever(addr, rsaKey=rsaKey, onClientJoin=self.onJoin, onClientLeave=self.onLeave, onReceiveData=self.receive)
            case _:
                self.gameServer = None
        if self.gameServer != None:
            self.severThread = Thread(target=self.gameServer.mainloop, daemon=True)
        else:
            raise ValueError(f"No such game with id={gameId}")
            
        
    def start(self) -> None:
        self.severThread.start()
        
    def stop(self) -> None:
        self.gameServer.udpServer.isRunning.clear()
        self.gameServer.isRunning = False
                
    def onJoin(self, addr):
        self.members.append(addr)
        self.heartbeat = True
    
    def onLeave(self, addr):
        self.members.remove(addr)
        if self.isEmpty():
            self.heartbeat = datetime.datetime.now()
    
    def receive(self, addr, data):
        pass
    
    def isNotFull(self) -> bool:
        return self.gameServer.isNotFull()
    
    def isEmpty(self) -> bool:
        # return self.gameServer.isEmpty()
        return len(self.members) == 0
    
    def getMembers(self) -> list[int]:
        return self.members
    
    def getGame(self) -> int|None:
        return self.gameId
    
    def getAddr(self) -> tuple[str, int]:
        return self.addr
    
    def isPrune(self):
        if isinstance(self.heartbeat, datetime.datetime):
            delta = self._heartbeatDelta()
            if delta > PRUNE_TIME: # check if server has been empty for > PRUNE_TIME
                return True
        return False
    
    def _heartbeatDelta(self):
        return (datetime.datetime.now() - self.heartbeat).seconds
            
    
class LobbyHandler:
    _autoIncrement: int
    lobbies: list[Lobby]
    lobbiesLock: Lock
    pruneThread: Thread
    isRunning: bool
    rsaKey: None
    
    def __init__(self, rsaKey=None):
        self.nextId = 1
        self.lobbies = []
        self.lobbiesLock = Lock()
        self.pruneThread = Thread(target=self.prune, daemon=True)
        self.isRunning = True
        self.rsaKey = rsaKey
        # 
        self.startPrune()
        
    @property
    def nextId(self):
        id = self._autoIncrement
        self._autoIncrement += 1
        return id
    
    @nextId.setter
    def nextId(self, v:int):
        self._autoIncrement = v
        
    def stopPrune(self):
        self.isRunning = False
        
    def startPrune(self):
        self.pruneThread.start()
    
    def createLobby(self, addr, gameId:int|None=None) -> Lobby:
        with self.lobbiesLock:
            id = self.nextId
            addr = (addr[0], addr[1]+id)
            l = Lobby(id, addr, gameId=gameId, rsaKey=self.rsaKey)
            l.start()
            self.lobbies.append(l)
            return l
        
    def deleteLobby(self, addr) -> bool|None:
        with self.lobbiesLock:
            lobbyIndex = [index for index, lobby in enumerate(self.lobbies) if lobby.addr == addr][:1]
            lobbyIndex = lobbyIndex[0] if len(lobbyIndex) > 0 else None
            if lobbyIndex != None:
                self.lobbies[lobbyIndex].stop()
                del self.lobbies[lobbyIndex]
                return True
            else:
                raise ValueError(f"No such lobby addr {addr}")
                return False
        
    def getAll(self) -> list[Lobby]:
        with self.lobbiesLock:
            return self.lobbies
    
    def getNotFull(self) -> list[Lobby]:
        with self.lobbiesLock:
            return [lobby for lobby in self.lobbies if lobby.isNotFull()]
    
    def getLobby(self, lobbyId:int) -> Lobby:
        with self.lobbiesLock:
            lobby = [lobby for lobby in self.lobbies if lobby.id == lobbyId][:1]
            lobby = lobby[0] if len(lobby) > 0 else None
            return lobby
        
    def findLobbies(self, gameId:int) -> Lobby:
        with self.lobbiesLock:
            lobbies = [lobby for lobby in self.lobbies if lobby.isNotFull() and lobby.gameId ==  gameId]
            return lobbies
        
    def getMembers(self) -> dict[int, list[int]]:
        with self.lobbiesLock:
            return {lobby.id:lobby.members for lobby in self.lobbies}
            
    def prune(self):
        while self.isRunning:
            with self.lobbiesLock:
                lobbies = self.lobbies.copy()
            for lobby in lobbies:
                # print(f"{lobby}, {lobby.isPrune()}, {lobby.heartbeat}")
                if lobby.isPrune():
                    print(f"DELETING LOBBY {lobby} due to PRUNE ({lobby._heartbeatDelta()})")
                    self.deleteLobby(lobby.addr)
            time.sleep(PRUNE_TIME)
>>>>>>> Stashed changes
