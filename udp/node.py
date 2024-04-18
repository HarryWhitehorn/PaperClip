import socket
import packet
import threading
import queue
import time
import auth

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
    _sequenceId = 0
    sequenceIdLock = threading.Lock()
    isRunning = threading.Event()
    rsaKey = None
    cert = None
    ecKey = None
    sessionKey = None
    fragBuffer:dict[int,list[packet.Packet]] = {}
    
    def __init__(self, addr):
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.addr = addr
        self.sequenceId = 0
        self.isRunning.set()
        self.sent_ack_buffer = [None for _ in range(packet.SEQUENCE_ID_SIZE)]
        self.recv_ack_buffer = [None for _ in range(packet.SEQUENCE_ID_SIZE)]
        self.queue = queue.Queue()
        self.rsaKey = auth.generateRsaKey()
        self.cert = auth.generateCertificate(self.rsaKey)
        self.ecKey = auth.generateEcKey()
        self.socket.bind(self.addr)
        # threads
        self.inboundThread = threading.Thread(target=self.listen, daemon=True)
        self.outboundThread = threading.Thread(target=self.sendQueue, daemon=True)
        
    @property
    def sequenceId(self):
        return self._sequenceId
    
    @sequenceId.setter
    def sequenceId(self, v):
        self._sequenceId = v % 2**packet.SEQUENCE_ID_SIZE
        
    def incrementSequenceId(self):
        with self.sequenceIdLock:
            self.sequenceId += 1
        
    @property
    def host(self):
        return self.addr[0]
    
    @property
    def port(self):
        return self.addr[1]
    
    def getSentAckBit(self, addr, p):
        return self.sent_ack_buffer[p.sequence_id]
    
    def setSentAckBit(self, addr, ackBit, v:bool):
        self.sent_ack_buffer[ackBit] = v
        
    def getRecvAckBit(self, addr, p):
        return self.recv_ack_buffer[p.sequence_id]
    
    def setRecvAckBit(self, addr, ackBit, v:bool):
        self.recv_ack_buffer[ackBit] = v
        
    def getSessionKey(self, addr):
        return self.sessionKey
    
    def getFragBuffer(self, addr):
        return self.fragBuffer
    
    # sends
    def sendPacket(self, addr, p):
        print(f"{bcolors.OKBLUE}> {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
        self.socket.sendto(p.pack(p), (addr[0],addr[1]))
        
    def sendQueue(self):
        while self.isRunning.is_set():
            addr, p = self.queue.get()
            if p.flags[packet.Flag.RELIABLE.value]:
                if self.getSentAckBit(addr, p):
                    continue
                else:
                    self.sendPacket(addr, p)
                    self.queue.task_done()
                    self.queue.put((addr,p))
            else:
                self.sendPacket(addr, p)
                self.queue.task_done()
            time.sleep(SLEEP_TIME)
        else:
            print("| sendQueue thread stopping...")
            
    def queuePacket(self, addr, p:packet.Packet):
        if p.flags[packet.Flag.RELIABLE.value]:
            # self.sent_ack_buffer[p.sequence_id] = False
            self.setSentAckBit(addr, p.sequence_id, False)
        if p.flags[packet.Flag.CHECKSUM.value]:
            p.setChecksum()
        if p.flags[packet.Flag.COMPRESSED.value]:
            p.compressData()
        if p.flags[packet.Flag.ENCRYPTED.value]:
            p.encryptData(self.getSessionKey(addr))
        if p.flags[packet.Flag.FRAG.value]:
            frags = p.fragment()
            for frag in frags:
                self.queue.put((addr, frag))
        else:
            self.queue.put((addr, p))
    
    def queueDefault(self, addr, flags=[0 for _ in range(packet.FLAGS_SIZE)], data=None):
        p = packet.Packet(sequence_id=self.sequenceId, flags=flags, data=data)
        self.incrementSequenceId()
        self.queuePacket(addr, p)
        
    def queueACK(self, addr, ackId, flags=[0 for _ in range(packet.FLAGS_SIZE)], data=None):
        p = packet.AckPacket(sequence_id=self.sequenceId, flags=flags, ack_id=ackId, ack_bits=self.recv_ack_buffer, data=data)
        self.incrementSequenceId()
        self.queuePacket(addr, p)
        
    def queueAuth(self, addr, cert, publicEc):
        p = packet.AuthPacket(sequence_id=self.sequenceId, certificate=cert, public_key=publicEc)
        self.incrementSequenceId()
        self.queuePacket(addr, p)
        
    def queueFinished(self, addr, seqId, sessionKey):
        finished = Node._generateFinished(sessionKey)
        self.queueACK(addr, seqId, data=finished)
        
    @staticmethod
    def _generateFinished(sessionKey):
        return auth.generateFinished(sessionKey, finishedLabel=b"node finished", messages=b"\x13") # TODO: give appropriate values for label and messages
    
    # receives
    def receivePacket(self):
        data, addr = self.socket.recvfrom(BUFFER_SIZE)
        p = packet.unpack(data)
        return p, addr
    
    def receive(self, p, addr):
        if p != None:
            if self.handleFlags(p, addr):
                print(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                match (p.packet_type):
                    case packet.Type.DEFAULT:
                        return self.receiveDefault(p, addr)
                    case packet.Type.ACK:
                        return self.receiveAck(p, addr)
                    case packet.Type.AUTH:
                        return self.receiveAuth(p, addr)
                    case _:
                        raise TypeError(f"Unknown packet type '{p.packet_type}' for packet {p}")
    
    def receiveDefault(self, p:packet.Packet, addr):
        pass
        return (p,addr)
    
    def receiveAck(self, p, addr):
        # self.sent_ack_buffer[p.ack_id] = True
        self.setSentAckBit(addr, p.ack_id, True)
        return (p, addr)
        
    def receiveAuth(self, p, addr):
        raise NotImplementedError(f"Node should not receive auth. A child class must overwrite.")
        return (p, addr)
        
    def listen(self):
        print(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            self.receive(p, addr)
        else:
            print("| listen thread stopping...")
        
    # flags handle
    def handleFlags(self, p:packet.Packet, addr) -> bool:
        # defrag -> decrypt -> decompress -> validate checksum -> reliable
        if self.handleFrag(p, addr):
            return False
        else:
            self.handleEncrypted(p, addr)
            self.handleCompressed(p, addr)
            self.handleChecksum(p, addr)
            self.handleReliable(p, addr)
            return True
        
    def handleReliable(self, p:packet.Packet, addr) -> bool:
        if p.flags[packet.Flag.RELIABLE.value]:
            # self.recv_ack_buffer[p.sequence_id] = True
            self.setRecvAckBit(addr, p.sequence_id, True)
            self.queueACK(addr, p.sequence_id)
            return True
        else:
            return False
        
    def handleFrag(self, p:packet.Packet, addr) -> bool:
        if p.flags[packet.Flag.FRAG.value]:
            print(f"\t{bcolors.OKBLUE}< {addr} :{bcolors.ENDC}{bcolors.WARNING} FRAG {p.fragment_id}/{p.fragment_number} {p}{bcolors.ENDC}")
            if not p.sequence_id in self.getFragBuffer(addr):
                self.getFragBuffer(addr)[p.sequence_id] = [None for _ in range(p.fragment_number)]
            self.getFragBuffer(addr)[p.sequence_id][p.fragment_id] = p
            if all(self.getFragBuffer(addr)[p.sequence_id]):
                defrag = p.defragment(self.getFragBuffer(addr)[p.sequence_id])
                del self.getFragBuffer(addr)[p.sequence_id]
                self.receive(defrag, addr)
            return True
        else:
            return False
        
    def handleCompressed(self, p:packet.Packet, addr) -> bool:
        if p.flags[packet.Flag.COMPRESSED.value]:
            p.decompressData()
            return True
        else:
            return False
            
    def handleEncrypted(self, p:packet.Packet, addr) -> bool:
        if p.flags[packet.Flag.ENCRYPTED.value]:
            p.decryptData(self.getSessionKey(addr))
            return True
        else:
            return False
        
    def handleChecksum(self, p:packet.Packet, addr) -> bool:
        if p.flags[packet.Flag.CHECKSUM.value]:
            if not p.validateChecksum():
                raise ValueError(f"\tInvalid checksum: {p}")
            else:
                print(f"\tValid checksum: {p}")
            return True
        else:
            return False
            
    # util
    @staticmethod
    def encryptData(data:bytes, sessionKey:bytes, initVector:bytes=auth.generateInitVector()) -> tuple[bytes, bytes]:
        cipher, initVector = auth.generateCipher(sessionKey, initVector)
        data = auth.encryptBytes(cipher, data)
        return data, initVector
    
    @staticmethod
    def decryptData(data:bytes, sessionKey:bytes, initVector:bytes) -> tuple[bytes, bytes]:
        cipher, initVector = auth.generateCipher(sessionKey, initVector)
        data = auth.decryptBytes(cipher, data)
        return data, initVector
    
    # misc
    def startThreads(self):
        self.inboundThread.start()
        self.outboundThread.start()
                   
    @staticmethod
    def validateCert(cert):
        # TODO: valid cert check
        return True
            
    
if __name__ == "__main__":
    nOne = Node((C_HOST, C_PORT))
    