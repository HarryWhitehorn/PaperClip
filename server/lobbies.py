import datetime
import time
from threading import Lock, Thread

from rps.server import Server as RpsSever
from udp import bcolors
from udp.server import Server

from . import PRUNE_TIME, logger


class Lobby:
    id: int
    members: list[int]
    addr: tuple[str, int]
    gameServer: Server
    severThread: Thread
    gameId: int | None
    heartbeat: bool | datetime.datetime

    def __init__(
        self, id: int, addr: tuple[str, int], gameId: int | None = None, rsaKey=None
    ) -> None:
        self.id = id
        self.members = []
        self.addr = addr
        self.gameId = gameId
        self.heartbeat = datetime.datetime.now()
        match gameId:
            case 1:
                self.gameServer = RpsSever(
                    addr,
                    rsaKey=rsaKey,
                    onClientJoin=self.onJoin,
                    onClientLeave=self.onLeave,
                    onReceiveData=self.receive,
                )
            case _:
                self.gameServer = None
        if self.gameServer is not None:
            self.severThread = Thread(
                name=f"{self.id}:Gameloop", target=self.gameServer.mainloop, daemon=True
            )
        else:
            raise ValueError(f"No such game with id={gameId}")

    def __str__(self) -> str:
        return f"<id={self.id}, addr={self.addr}, gameId=<{self.gameId}>>"

    def start(self) -> None:
        self.severThread.start()

    def quit(self) -> None:
        self.gameServer.isRunning = False
        self.gameServer.quit()

    def onJoin(self, addr: tuple[str, int], accountId: int) -> None:
        self.members.append(accountId)
        self.heartbeat = True

    def onLeave(self, addr: tuple[str, int], accountId: int) -> None:
        self.members.remove(accountId)
        if self.isEmpty():
            self.heartbeat = datetime.datetime.now()

    def receive(self, addr: tuple[str, int], data: bytes) -> None:
        pass

    def isNotFull(self) -> bool:
        return self.gameServer.isNotFull()

    def isEmpty(self) -> bool:
        return len(self.members) == 0

    def getMembers(self) -> list[int]:
        return self.members

    def getGame(self) -> int | None:
        return self.gameId

    def getAddr(self) -> tuple[str, int]:
        return self.addr

    def isPrune(self) -> bool:
        if isinstance(self.heartbeat, datetime.datetime):
            delta = self._heartbeatDelta()
            if delta > PRUNE_TIME:  # check if server has been empty for > PRUNE_TIME
                return True
        return False

    def _heartbeatDelta(self) -> int:
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
        self.pruneThread = Thread(name="HOST:Prune", target=self.prune, daemon=True)
        self.isRunning = True
        self.rsaKey = rsaKey
        #
        self.startPrune()

    @property
    def nextId(self) -> int:
        id = self._autoIncrement
        self._autoIncrement += 1
        return id

    @nextId.setter
    def nextId(self, v: int) -> None:
        self._autoIncrement = v

    def stopPrune(self) -> None:
        self.isRunning = False

    def startPrune(self) -> None:
        self.pruneThread.start()

    def createLobby(self, addr: tuple[str, int], gameId: int | None = None) -> Lobby:
        with self.lobbiesLock:
            id = self.nextId
            addr = (addr[0], addr[1] + id)
            lobby = Lobby(id, addr, gameId=gameId, rsaKey=self.rsaKey)
            lobby.start()
            self.lobbies.append(lobby)
            return lobby

    def deleteLobby(self, addr) -> bool | None:
        with self.lobbiesLock:
            lobbyIndex = [
                index for index, lobby in enumerate(self.lobbies) if lobby.addr == addr
            ][:1]
            lobbyIndex = lobbyIndex[0] if len(lobbyIndex) > 0 else None
            if lobbyIndex is not None:
                self.lobbies[lobbyIndex].quit()
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

    def getMember(self, accountId: int) -> list[Lobby]:
        with self.lobbiesLock:
            return [
                lobby
                for lobby in self.lobbies
                if lobby.isNotFull() and accountId in lobby.getMembers()
            ]

    def getLobby(self, lobbyId: int) -> Lobby:
        with self.lobbiesLock:
            lobby = [lobby for lobby in self.lobbies if lobby.id == lobbyId][:1]
            lobby = lobby[0] if len(lobby) > 0 else None
            return lobby

    def findLobbies(self, gameId: int) -> Lobby:
        with self.lobbiesLock:
            lobbies = [
                lobby
                for lobby in self.lobbies
                if lobby.isNotFull() and lobby.gameId == gameId
            ]
            return lobbies

    def getMembers(self) -> dict[int, list[int]]:
        with self.lobbiesLock:
            return {lobby.id: lobby.members for lobby in self.lobbies}

    def prune(self) -> None:
        while self.isRunning:
            with self.lobbiesLock:
                lobbies = self.lobbies.copy()
            for lobby in lobbies:
                if lobby.isPrune():
                    logger.info(
                        f"{bcolors.FAIL}# Lobby {lobby} was removed due to PRUNE (delta={lobby._heartbeatDelta()}){bcolors.ENDC}"
                    )
                    self.deleteLobby(lobby.addr)
            time.sleep(PRUNE_TIME)

    def quit(self) -> None:
        logger.info(f"{bcolors.FAIL}# Shuting down lobbies{bcolors.ENDC}")
        self.isRunning = False
        with self.lobbiesLock:
            lobbies = self.lobbies.copy()
        for lobby in lobbies:
            lobby.quit()
        logger.info(f"{bcolors.FAIL}# Shuting down complete{bcolors.ENDC}")
