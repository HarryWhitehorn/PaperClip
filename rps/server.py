import json
from queue import Empty, Queue
from threading import Lock

from udp.auth import rsa
from udp.server import Server as UdpServer

from . import MAX_PLAYERS, QUEUE_TIMEOUT, Choice, Outcome


class Server:
    isRunning: bool
    recvBuffer: Queue
    players: dict[tuple[str, int], dict[str, int]]
    playersLock: Lock
    udpServer: UdpServer
    onClientJoin: None
    onClientLeave: None
    onReceiveData: None

    def __init__(
        self,
        addr: tuple[str, int],
        rsaKey: rsa.RSAPrivateKey | None = None,
        onClientJoin=None,
        onClientLeave=None,
        onReceiveData=None,
    ):
        self.isRunning = True
        self.recvQueue = Queue()
        self.players = {}
        self.playersLock = Lock()
        self.onClientJoin = onClientJoin
        self.onClientLeave = onClientLeave
        self.onReceiveData = onReceiveData
        self.udpServer = UdpServer(
            addr,
            maxClients=MAX_PLAYERS,
            rsaKey=rsaKey,
            onClientJoin=self.playerJoin,
            onClientLeave=self.playerLeave,
            onReceiveData=self.receive,
        )

    def send(self, addr: tuple[str, int], data: dict) -> None:
        self.udpServer.queueDefault(addr, data=self.encodeData(data))

    def receive(self, addr: tuple[str, int], data: bytes) -> None:
        self.recvQueue.put((addr, self.decodeData(data)))
        if self.onReceiveData:
            self.onReceiveData(addr, data)

    @staticmethod
    def encodeData(data: dict) -> bytes:
        return json.dumps(data).encode()

    @staticmethod
    def decodeData(data: bytes) -> dict:
        return json.loads(data.decode())

    @staticmethod
    def evaluateWin(choiceOne: int, choiceTwo: int) -> int:
        match choiceOne:
            case Choice.ROCK:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.DRAW
                    case Choice.PAPER:
                        return Outcome.LOOSE
                    case Choice.SCISSORS:
                        return Outcome.WIN
                    case _:
                        raise ValueError
            case Choice.PAPER:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.WIN
                    case Choice.PAPER:
                        return Outcome.DRAW
                    case Choice.SCISSORS:
                        return Outcome.LOOSE
                    case _:
                        raise ValueError
            case Choice.SCISSORS:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.LOOSE
                    case Choice.PAPER:
                        return Outcome.WIN
                    case Choice.SCISSORS:
                        return Outcome.DRAW
                    case _:
                        raise ValueError
            case _:
                raise ValueError

    @staticmethod
    def evaluatePlayerChoices(choices: list[tuple[tuple[str, int], int]]):
        outcomes = [
            (choices[0][0], Server.evaluateWin(choices[0][1], choices[1][1])),
            (choices[1][0], Server.evaluateWin(choices[1][1], choices[0][1])),
        ]
        return outcomes

    def getChoices(self) -> list[tuple[tuple[str, int], int]]:
        choices = {}
        while self.isRunning:
            try:
                addr, data = self.recvQueue.get(timeout=QUEUE_TIMEOUT)
                choices[addr] = data["choice"]
                if len(choices) == 2:
                    choices = [(addr, choice) for addr, choice in choices.items()]
                    self.recvQueue.task_done()
                    return choices
            except Empty:
                pass  # check still running

    def playerJoin(self, addr: tuple[str, int], accountId: int) -> None:
        with self.playersLock:
            self.players[addr] = {"score": 0, "accountId": accountId}
        if self.onClientJoin:
            self.onClientJoin(addr, accountId)

    def playerLeave(self, addr: tuple[str, int], accountId: int) -> None:
        with self.playersLock:
            # TODO: submit score
            del self.players[addr]
        if self.onClientLeave:
            self.onClientLeave(addr, accountId)

    def isNotFull(self) -> bool:
        return self.udpServer.isNotFull()

    def isEmpty(self) -> bool:
        return self.udpServer.isEmpty()

    def getPlayers(self) -> dict[tuple[str, int], dict[str, int]]:
        with self.playersLock:
            return self.players.copy()

    def getPlayer(self, addr: tuple[str, int]) -> int:
        with self.playersLock:
            if addr in self.players:
                return self.players[addr]
            else:
                return None

    def setPlayer(self, addr: tuple[str, int], v: int) -> None:
        with self.playersLock:
            if addr in self.players:
                self.players[addr] = v

    def incrementPlayer(self, addr: tuple[str, int]) -> None:
        with self.playersLock:
            self.players[addr]["score"] += 1

    def getAccountId(self, addr: tuple[str, int]) -> int:
        with self.playersLock:
            return self.players[addr]["accountId"]

    def getAccountIds(self, addr: tuple[str, int]) -> list[int]:
        with self.playersLock:
            return [player["accountId"] for player in self.players.values()]

    @property
    def playerCount(self) -> int:
        with self.playersLock:
            return len(self.players)

    def mainloop(self) -> None:
        self.udpServer.startThreads()
        try:
            while self.isRunning:
                if self.playerCount == MAX_PLAYERS:
                    choices = self.getChoices()
                    outcomes = self.evaluatePlayerChoices(choices)
                    replies = {}
                    for addr, outcome in outcomes:
                        replies[addr] = {
                            "outcome": outcome,
                            "choice": [v for k, v in choices if k == addr][0],
                            "otherChoice": [v for k, v in choices if k != addr][0],
                        }
                        if outcome == Outcome.WIN:
                            self.incrementPlayer(addr)
                    scores = self.getPlayers()
                    for addr in replies:
                        replies[addr] |= {
                            "score": scores[addr],
                            "otherScore": [v for k, v in scores.items() if k != addr][
                                0
                            ],
                        }
                        self.send(addr, replies[addr])
        finally:
            self.quit()

    def quit(self) -> None:
        self.isRunning = False
        self.udpServer.quit()
