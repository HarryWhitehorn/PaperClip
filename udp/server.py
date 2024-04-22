from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from threading import Thread, Lock, Event
from datetime import datetime
import requests
import base64
import socket
import json
import time

from . import bcolors, node, packet, auth, logger

HEARTBEAT_MAX_TIME = 120 # seconds
HEARTBEAT_MIN_TIME = 30 # seconds
MAX_CLIENTS = float("inf") # no limit

class Server(node.Node):
    clients: dict[tuple[str, int], node.Node]
    clientsLock: Lock
    clientDeleteEvent: Event
    rsaKey: RSAPrivateKey|None
    heartbeatThread: Thread
    onClientJoin: None
    onClientLeave: None
    maxClients: int
    
    def __init__(self, addr, maxClients:int=MAX_CLIENTS, rsaKey:RSAPrivateKey|None=None, onClientJoin=None, onClientLeave=None, onReceiveData=None):
        self.clients = {}
        self.clientsLock = Lock()
        self.clientDeleteEvent = Event()
        self.clientDeleteEvent.set()
        self.rsaKey = rsaKey if rsaKey != None else auth.generateRsaKey()
        self.heartbeatThread = Thread(target=self.heartbeat, daemon=True)
        self.onClientJoin = onClientJoin
        self.onClientLeave = onClientLeave
        self.maxClients = maxClients
        s = socket.socket(type=socket.SOCK_DGRAM)
        super().__init__(addr, cert=auth.generateUserCertificate(self.rsaKey), socket=s, onReceiveData=onReceiveData)
        self.bind(self.addr)
            
    def receiveDefault(self, p, addr):
        super().receiveDefault(p, addr)
        # TODO: NOTE: DEBUG REMOVE
        if p.data == b"KILL":
            self.isRunning.clear()
        if p.data == b"TEST":
            self._testPacket(addr)
            
    def receiveAck(self, p, addr):
            super().receiveAck(p, addr)
            if p.data != None and not self.getHandshake(addr): # ack has payload & client has not completed handshake => validate handshake
                if not self.validateHandshake(addr, p.data):
                    # raise ValueError(f"Local finished value does not match peer finished value {p.data}")
                    logger.error(f"Local finished value does not match peer finished value {p.data}")
                else:
                    # print(f"{bcolors.OKGREEN}# Handshake with {addr} successful.{bcolors.ENDC}")
                    logger.info(f"{bcolors.OKGREEN}# Handshake with {addr} successful.{bcolors.ENDC}")
                    if self.onClientJoin:
                        self.onClientJoin(addr)
                 
    def receiveAuth(self, p:packet.AuthPacket, addr):
        if not addr in self.clients: # new client
            if self.isNotFull(): # check space
                # print(f"{bcolors.WARNING}# Handshake with {addr} starting.{bcolors.ENDC}")
                logger.info(f"{bcolors.WARNING}# Handshake with {addr} starting.{bcolors.ENDC}")
                if not self.validateCertificate(p.certificate):
                    # raise ValueError(f"Invalid peer cert {p.certificate}")
                    logger.error(f"Invalid peer cert {p.certificate}")
                else:
                    self.makeClient(addr, p.certificate)
                    self.regenerateEcKey(addr)
                    sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
                    self.setSessionKey(addr,sessionKey)
                    self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                    self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
            else:
                # print(f"{bcolors.FAIL}# Handshake with {addr} denied due to NO_SPACE.{bcolors.ENDC}")
                logger.warning(f"{bcolors.FAIL}# Handshake with {addr} denied due to NO_SPACE.{bcolors.ENDC}")
                # ToDo: send no space ERROR
        else:
            sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
        if addr in self.clients:
            if self.getSessionKey(addr) !=  sessionKey: # new client sessionKey
                # print(f"{bcolors.WARNING}# Handshake with {addr} reset.{bcolors.ENDC}")
                logger.info(f"{bcolors.WARNING}# Handshake with {addr} reset.{bcolors.ENDC}")
                if not self.validateCertificate(p.certificate):
                    # raise ValueError(f"Invalid peer cert {p.certificate}")
                    logger.warning(f"Invalid peer cert {p.certificate}")
                else:
                    self.regenerateEcKey(addr)
                    # self.clients[addr].cert = p.certificate # shouldn't change
                    sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
                    self.setSessionKey(addr,sessionKey) # make new session key
                    self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                    self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        return (p, addr)
        
    def _testPacket(self, addr):
        flags=packet.lazyFlags(packet.Flag.FRAG ,packet.Flag.RELIABLE)
        self.queueDefault(addr, flags=flags, data=b"Hello World To You Too")
    
    def getSessionKey(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].sessionKey
        
    def setSessionKey(self, clientAddr, sessionKey:bytes):
        with self.clientsLock:
            self.clients[clientAddr].sessionKey = sessionKey
    
    def getHandshake(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].handshake
    
    def getSentAckBit(self, clientAddr, p):
        with self.clientsLock:
            return self.clients[clientAddr].sentAckBits[p.sequence_id]
    
    def setSentAckBit(self, clientAddr, ackBit, v:bool):
        with self.clientsLock:
            self.clients[clientAddr].sentAckBits[ackBit] = v
        
    def getSentAckBits(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].sentAckBits
        
    def getRecvAckBit(self, clientAddr, p):
        with self.clientsLock:
            return self.clients[clientAddr].recvAckBits[p.sequence_id]
    
    def getRecvAckBits(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].recvAckBits
    
    def setRecvAckBit(self, clientAddr, ackBit, v:bool):
        with self.clientsLock:
            self.clients[clientAddr].recvAckBits[ackBit] = v
        
    def getNewestSeqId(self, clientAddr):
        with self.clientsLock:
            if clientAddr in self.clients:
                return self.clients[clientAddr].newestSeqId
            else:
                return 0
        
    def setNewestSeqId(self, clientAddr, newSeqId:int):
        with self.clientsLock:
            if clientAddr in self.clients:
                self.clients[clientAddr].newestSeqId = newSeqId
        
    def getFragBuffer(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].fragBuffer
    
    def getEcKey(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].ecKey
    
    def getSequenceId(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].sequenceId
    
    def getQueue(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].queue
    
    def getSequenceIdLock(self, clientAddr):
        with self.clientsLock:
            return self.clients[clientAddr].sequenceIdLock
    
    def incrementSequenceId(self, clientAddr) -> None:
        with self.getSequenceIdLock(clientAddr):
            with self.clientsLock:
                self.clients[clientAddr].sequenceId += 1
            
    def getHeartbeat(self, clientAddr) -> datetime:
        with self.clientsLock:
            return self.clients[clientAddr].heartbeat
    
    def setHeartbeat(self, clientAddr, v:datetime) -> None:
        with self.clientsLock:
            self.clients[clientAddr].heartbeat = v
            
    def regenerateEcKey(self, clientAddr) -> None:
        with self.clientsLock:
            self.clients[clientAddr].regenerateEcKey()
            
    def checkClientExists(self, clientAddr) -> bool:
        with self.clientsLock:
            return clientAddr in self.clients
        
    def validateHandshake(self, clientAddr, finished:bytes):
        with self.clientsLock:
            return self.clients[clientAddr].validateHandshake(finished)
        
    def getClientLength(self):
        with self.clientsLock:
            return len(self.clients)
        
    def isNotFull(self) -> bool:
        with self.clientsLock:
            return len(self.clients) < self.maxClients # check space

    def isEmpty(self) -> bool:
        with self.clientsLock:
            return len(self.clients) == 0

    def listen(self):
        # print(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        logger.info(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            if p != None and addr != None:
                if self.checkClientExists(addr): # client exists
                    self.setHeartbeat(addr, datetime.now())
                    if self.getHandshake(addr): # client handshake complete => allow all packet types
                        self.receive(p, addr)
                    else:
                        if p.packet_type in (packet.Type.AUTH, packet.Type.ACK): # client handshake incomplete => drop all non-AUTH | non-ACK packets
                            self.receive(p, addr)
                else:
                    if p.packet_type == packet.Type.AUTH: # client not exists => drop all non-AUTH packets
                        self.receive(p, addr)
                    else:
                        # print(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
                        logger.warning(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
        else:
            # print("| listen thread stopping...")
            logger.info("| listen thread stopping...")
            
    def heartbeat(self):
        while self.isRunning.is_set():
            time.sleep(HEARTBEAT_MIN_TIME)
            with self.clientsLock:
                clients = [k for k in self.clients.keys()]
            for clientAddr in clients:
                heartbeat = self.getHeartbeat(clientAddr)
                delta = (datetime.now()-heartbeat).seconds
                if delta > HEARTBEAT_MAX_TIME:
                    # send heartbeat timeout error
                    self.removeClient(clientAddr, debugStr=f"due to heartbeat timeout (last contact was {heartbeat})")
                elif delta > HEARTBEAT_MIN_TIME:
                    self.queueHeartbeat(clientAddr, heartbeat=False)
        else:
            # print("| heartbeat thread stopping...")
            logger.info("| heartbeat thread stopping...")
                    
    def makeClient(self, clientAddr, cert):
        c = node.Node(clientAddr, cert=cert, sendLock=self.sendLock, socket=self.socket)
        c.outboundThread.start()
        with self.clientsLock:
            self.clients[clientAddr] = c
    
    def removeClient(self, clientAddr, debugStr=""):
        with self.clientsLock:
            # print(f"{bcolors.FAIL}# Client {clientAddr} was removed{' '+debugStr}.{bcolors.ENDC}")
            logger.info(f"{bcolors.FAIL}# Client {clientAddr} was removed{' '+debugStr}.{bcolors.ENDC}")
            self.clients[clientAddr].isRunning.clear()
            del self.clients[clientAddr]
            if self.onClientLeave:
                self.onClientLeave(clientAddr)
    
    # misc
    def startThreads(self):
        super().startThreads()
        self.heartbeatThread.start()
        
    def validateCertificate(self, certificate): 
        url = f"http://{self.host}:5000/auth/certificate/validate"
        headers = {"Content-Type":"application/json"}
        certificate = base64.encodebytes(auth.getDerFromCertificate(certificate)).decode()
        data = {"certificate": certificate}
        r = requests.get(url, headers=headers, data=json.dumps(data))
        if r.status_code == 200:
            return r.json()["valid"]
        else:
            return False
        
if __name__ == "__main__":
    from time import sleep
    
    from . import S_HOST, S_PORT
    
    s = Server((S_HOST,S_PORT))
    print("\n"*4+"Press <enter> to kill client.")
    s.startThreads()
    input()
    s.isRunning.clear()
    sleep(1)
    print("DONE")