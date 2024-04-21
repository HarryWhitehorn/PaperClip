from queue import Queue
from threading import Lock
import random
import json

from udp.server import Server as UdpServer

from . import bcolors, Choice, Outcome

MAX_PLAYERS = 2

class Server:
    isRunning:bool
    recvBuffer: Queue
    players: dict[tuple[str, int], int]
    playersLock: Lock
    udpServer: UdpServer
    onClientJoin: None
    onClientLeave: None
    onReceiveData: None
    
    def __init__(self, addr, onClientJoin=None, onClientLeave=None, onReceiveData=None):
        self.isRunning = True
        self.recvQueue = Queue()
        self.players = {}
        self.playersLock = Lock()
        self.onClientJoin = onClientJoin
        self.onClientLeave = onClientLeave
        self.onReceiveData = onReceiveData
        self.udpServer = UdpServer(addr, maxClients=MAX_PLAYERS, onClientJoin=self.playerJoin, onClientLeave=self.playerLeave, onReceiveData=self.receive)
        
    def send(self, addr, data:json):
        self.udpServer.queueDefault(addr, data=self.encodeData(data))
    
    def receive(self, addr, data:bytes):
        self.recvQueue.put((addr,self.decodeData(data)))
        if self.onReceiveData:
            self.onReceiveData(addr, data)
        
    @staticmethod
    def encodeData(data:json):
        return json.dumps(data).encode()
    
    @staticmethod
    def decodeData(data:bytes):
        return json.loads(data.decode())
    
    @staticmethod
    def evaluateWin(choiceOne:int, choiceTwo:int):
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
    def evaluatePlayerChoices(choices:list[tuple[tuple[str,int],int]]):
        outcomes = [(choices[0][0],Server.evaluateWin(choices[0][1], choices[1][1])), (choices[1][0],Server.evaluateWin(choices[1][1], choices[0][1]))]
        return outcomes
    
    def getChoices(self):
        choices = {}
        while True:
            addr, data = self.recvQueue.get()
            choices[addr] = data["choice"]
            if len(choices) == 2:
                break
        choices = [(addr, choice) for addr, choice in choices.items()]
        self.recvQueue.task_done()
        return choices
    
    def playerJoin(self, addr):
        with self.playersLock:
            self.players[addr] = 0
        if self.onClientJoin:
            self.onClientJoin(addr)
        
    def playerLeave(self, addr):
        with self.playersLock:
            del self.players[addr]
        if self.onClientLeave:
            self.onClientLeave
            
    def getPlayers(self):
        with self.playersLock:
            return self.players.copy()
        
    def getPlayer(self, addr) -> int:
        with self.playersLock:
            if addr in self.players:
                return self.players[addr]
            else:
                return None
    
    def setPlayer(self, addr, v:int) -> None:
        with self.playersLock:
            if addr in self.players:
                self.players[addr] = v
                
    def incrementPlayer(self, addr) -> None:
        with self.playersLock:
            self.players[addr] += 1
        
    @property
    def playerCount(self):
        with self.playersLock:
            return len(self.players)
        
    def mainloop(self):
        self.udpServer.startThreads()
        try:
            while self.isRunning:
                if self.playerCount == MAX_PLAYERS:
                    choices = self.getChoices()
                    outcomes = self.evaluatePlayerChoices(choices)
                    replies = {}
                    for addr, outcome in outcomes:
                        replies[addr] = {"outcome":outcome, "choice":[v for k,v in choices if k == addr][0], "otherChoice":[v for k,v in choices if k != addr][0]}
                        if outcome == Outcome.WIN:
                            self.incrementPlayer(addr)
                    scores = self.getPlayers()
                    for addr in replies:
                        replies[addr] |= {"score":scores[addr], "otherScore":[v for k,v in scores.items() if k != addr][0]}
                        self.send(addr, replies[addr])
        finally:
            self.isRunning = False
            self.udpServer.isRunning.clear()
            