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
BUFFER_SIZE = 2048 #1024 TODO: frag
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
    
    def checkACKed(self, p):
        ackBit = self.sent_ack_buffer[p.sequence_id]
        return ackBit
    
    # sends
    def sendPacket(self, addr, p):
        # print(f"Sending {p} to {addr[1]}:{addr[0]}")
        print(f"{bcolors.OKBLUE}> {addr} :{bcolors.ENDC} {bcolors.OKGREEN}{p}{bcolors.ENDC}")
        self.socket.sendto(p.pack(p), (addr[0],addr[1]))
        
    def sendQueue(self):
        while self.isRunning.is_set():
            addr, p = self.queue.get()
            if p.flags[packet.Flag.RELIABLE.value]:
                if self.checkACKed(p):
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
    
    def queueDefault(self, addr, data, flags=[0,0,0,0]):
        p = packet.Packet(self.sequenceId, flags)
        self.incrementSequenceId()
        p.data = data
        if p.flags[packet.Flag.RELIABLE.value]:
            self.sent_ack_buffer[p.sequence_id] = False
        # self.sendPacket(addr, p)
        self.queue.put((addr,p))
        
    def queueACK(self, addr, seqId):
        p = packet.AckPacket(self.sequenceId, seqId, self.recv_ack_buffer)
        self.incrementSequenceId()
        # self.sendPacket(addr, p)
        self.queue.put((addr,p))
        
    def queueAuth(self, addr, cert, publicEc, finished=b"\x00"*32):
        p = packet.AuthPacket(self.sequenceId, cert, publicEc, finished)
        self.incrementSequenceId()
        self.queue.put((addr, p))
    
    # receives
    def receive(self):
        data, addr = self.socket.recvfrom(BUFFER_SIZE)
        p = packet.unpack(data)
        print(f"{bcolors.OKCYAN}< {addr} :{bcolors.ENDC} {bcolors.OKGREEN}{p}{bcolors.ENDC}")
        match (p.packet_type):
            case packet.Type.DEFAULT | packet.Type.FRAG:
                return self.receiveDefault(p, addr)
            case packet.Type.ACK:
                return self.receiveAck(p, addr)
            case packet.Type.AUTH:
                return self.receiveAuth(p, addr)
            case _:
                raise TypeError(f"Unknown packet type '{p.packet_type}' for packet {p}")
    
    def receiveDefault(self, p, addr):
        if p.flags[packet.Flag.RELIABLE.value]:
            self.recv_ack_buffer[p.sequence_id] = True
            self.queueACK(addr, p.sequence_id)
        return (p,addr)
    
    def _receiveFrag(self, p, addr):
        return (p,addr)
    
    def receiveAck(self, p, addr):
        self.sent_ack_buffer[p.ack_id] = True
        return (p, addr)
        
    def receiveAuth(self, p: packet.AuthPacket, addr):
        if self.sessionKey == None:
            self.sessionKey = auth.generateSessionKey(self.ecKey, p.publicEc)
            finished = auth.generateFinished(self.sessionKey, finishedLabel=b"node finished", messages=b"\x13") # TODO: give appropriate values for label and messages
            self.queueAuth(addr, self.cert, self.ecKey.public_key(), finished)
            if p.finished != b"\00"*32:
                assert p.finished == finished
                # TODO: send appropriate ACK (& wait for ACK else CRIT FAIL)
        return (p,addr)
        
    def listen(self):
        print(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        while self.isRunning.is_set():
            self.receive()
        else:
            print("| listen thread stopping...")
    
    # misc
    def mainloop(self):
        self.inboundThread = threading.Thread(target=self.listen, daemon=True)
        self.outboundThread = threading.Thread(target=self.sendQueue, daemon=True)
        self.inboundThread.start()
        self.outboundThread.start()
            
    
if __name__ == "__main__":
    nOne = Node((C_HOST, C_PORT))
    