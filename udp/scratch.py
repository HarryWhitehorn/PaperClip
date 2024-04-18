from threading import Thread, Lock, Event
from socket import socket as Socket
from socket import SOCK_DGRAM
import packet
from queue import Queue
import time
import auth
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

S_HOST = "127.0.0.1"
S_PORT = 2024
BUFFER_SIZE = 1024
C_HOST = "127.0.0.1"
C_PORT = S_PORT+1
SLEEP_TIME = 0.1

class Node:
    addr: tuple[str, int]
    _sequenceId: int
    sentAckBuffer = list[bool|None]
    recvAckBuffer = list[bool|None]
    fragBuffer: dict[int,list[packet.Packet]]
    queue: Queue
    # id
    rsaKey: RSAPrivateKey|None
    cert: Certificate|None
    # session
    ecKey: EllipticCurvePrivateKey
    sessionKey: bytes|None
    handshake: bool
    # threads
    inboundThread: Thread
    outboundThread: Thread
    sequenceIdLock: Lock
    isRunning: Event
    # socket
    socket: Socket|None
    
    def __init__(self, addr:tuple[str,int], socket:Socket|None=Socket(type=SOCK_DGRAM)) -> None:
        self.addr = addr
        self.sequenceId = 0
        self.sentAckBuffer = [None for _ in range(packet.ACK_BITS_SIZE)]
        self.recvAckBuffer = [None for _ in range(packet.ACK_BITS_SIZE)]
        self.fragBuffer = {}
        self.queue = Queue()
        # id
        self.rsaKey = auth.generateRsaKey()
        self.cert = auth.generateCertificate(self.rsaKey)
        # session
        self.ecKey = auth.generateEcKey()
        self.sessionKey = None
        self.handshake = False
        # threads
        self.inboundThread = Thread(daemon=True)
        self.outboundThread = Thread(daemon=True)
        self.sequenceIdLock = Lock()
        self.isRunning = Event()
        # socket
        self.socket = socket
    
    # properties
    @property
    def host(self) -> str:
        return self.addr[0]
    
    @property
    def port(self) -> int:
        return self.addr[1]
    
    @property
    def sequenceId(self) -> int:
        return self._sequenceId
    
    @sequenceId.setter
    def sequenceId(self, v:int) -> None:
        self._sequenceId = v % 2**packet.SEQUENCE_ID_SIZE
        
    def incrementSequenceId(self) -> None:
        with self.sequenceIdLock:
            self.sequenceId += 1
            
    def getSentAckBit(self, addr:tuple[str, int], p:packet.Packet) -> bool|None:
        return self.sent_ack_buffer[p.sequence_id]
    
    def setSentAckBit(self, addr:tuple[str, int], ackBit:int, v:bool) -> None:
        self.sent_ack_buffer[ackBit] = v
        
    def getRecvAckBit(self, addr:tuple[str, int], p:packet.Packet) -> bool|None:
        return self.recv_ack_buffer[p.sequence_id]
    
    def setRecvAckBit(self, addr:tuple[str, int], ackBit:int, v:bool) -> None:
        self.recv_ack_buffer[ackBit] = v
        
    def getSessionKey(self, addr:tuple[str, int]) -> int:
        return self.sessionKey
    
    def getFragBuffer(self, addr:tuple[str, int]) -> dict[int,list[packet.Packet]]:
        return self.fragBuffer