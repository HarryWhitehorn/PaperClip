from node import Node, bcolors
import auth
import packet
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import random
# from . import ADDR,PORT

class Server(Node):
    clients: dict[tuple[str, int], Node] = {}
    rsaKey: RSAPrivateKey|None
    
    def __init__(self, addr):
        self.rsaKey = auth.generateRsaKey()
        super().__init__(addr, cert=auth.generateCertificate(self.rsaKey))
        self.bind(self.addr)
            
    def receiveDefault(self, p, addr):
        super().receiveDefault(p, addr)
        if p.data == b"KILL":
            self.isRunning.clear()
        if p.data == b"TEST":
            self._testPacket(addr)
            
    def receiveAck(self, p, addr):
            super().receiveAck(p, addr)
            if p.data != None and not self.getHandshake(addr): # ack has payload & client has not completed handshake => validate handshake
                if not self.clients[addr].validateHandshake(p.data):
                    raise ValueError(f"Local finished value does not match peer finished value {p.data}")
                else:
                    print(f"{bcolors.OKGREEN}# Handshake with {self.addr} successful.{bcolors.ENDC}")
                 
    def receiveAuth(self, p:packet.AuthPacket, addr):
        if not addr in self.clients: # new client
            print(f"{bcolors.WARNING}# Handshake with {self.addr} starting.{bcolors.ENDC}")
            if not Node.validateCert(p.certificate):
                raise ValueError(f"Invalid peer cert {p.certificate}")
            else:
                self.clients[addr] = self.makeClient(addr, p.certificate)
                sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
                self.clients[addr].sessionKey = sessionKey
                self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        else:
            sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
        if self.getSessionKey(addr) !=  sessionKey: # new client sessionKey
            print(f"{bcolors.WARNING}# Handshake with {self.addr} reset.{bcolors.ENDC}")
            if not Node.validateCert(p.certificate):
                raise ValueError(f"Invalid peer cert {p.certificate}")
            else:
                self.clients[addr].regenerateEcKey()
                self.clients[addr].cert = p.certificate # shouldn't change
                self.clients[addr].sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key) # make new session key
                self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        return (p, addr)
        
    def _testPacket(self, addr):
        flags=packet.lazyFlags(packet.Flag.FRAG ,packet.Flag.RELIABLE)
        self.queueDefault(addr, flags=flags, data=b"Hello World To You Too")
    
    def getSessionKey(self, clientAddr):
        return self.clients[clientAddr].sessionKey
    
    def getHandshake(self, clientAddr):
        return self.clients[clientAddr].handshake
    
    def getSentAckBit(self, clientAddr, p):
        return self.clients[clientAddr].sentAckBits[p.sequence_id]
    
    def setSentAckBit(self, clientAddr, ackBit, v:bool):
        self.clients[clientAddr].sentAckBits[ackBit] = v
        
    def getSentAckBits(self, clientAddr):
        return self.clients[clientAddr].sentAckBits
        
    def getRecvAckBit(self, clientAddr, p):
        return self.clients[clientAddr].recvAckBits[p.sequence_id]
    
    def getRecvAckBits(self, clientAddr):
        return self.clients[clientAddr].recvAckBits
    
    def setRecvAckBit(self, clientAddr, ackBit, v:bool):
        self.clients[clientAddr].recvAckBits[ackBit] = v
        
    def getNewestSeqId(self, clientAddr):
        if clientAddr in self.clients:
            return self.clients[clientAddr].newestSeqId
        else:
            return 0
        
    def setNewestSeqId(self, clientAddr, newSeqId:int):
        if clientAddr in self.clients:
            self.clients[clientAddr].newestSeqId = newSeqId
        
    def getFragBuffer(self, clientAddr):
        return self.clients[clientAddr].fragBuffer
    
    def getEcKey(self, clientAddr):
        return self.clients[clientAddr].ecKey
    
    def getSequenceId(self, clientAddr):
        return self.clients[clientAddr].sequenceId
    
    def getQueue(self, clientAddr):
        return self.clients[clientAddr].queue
    
    def getSequenceIdLock(self, clientAddr):
        return self.clients[clientAddr].sequenceIdLock
    
    def incrementSequenceId(self, clientAddr) -> None:
        with self.getSequenceIdLock(clientAddr):
            self.clients[clientAddr].sequenceId += 1
               
    def listen(self):
        print(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            if addr in self.clients: # client exists
                if self.getHandshake(addr): # client handshake complete => allow all packet types
                    if p.packet_type == packet.Type.AUTH or True:# random.randint(0,10): # TODO: NOTE: FOR TESTING - REMOVE!!!
                        self.receive(p, addr)
                    else:
                        print(f"\t{bcolors.FAIL}{bcolors.BOLD}--DEBUG DROPPED PACKET {p}--{bcolors.ENDC}")
                else:
                    if p.packet_type in (packet.Type.AUTH, packet.Type.ACK): # client handshake incomplete => drop all non-AUTH | non-ACK packets
                        self.receive(p, addr)
            else:
                if p.packet_type == packet.Type.AUTH: # client not exists => drop all non-AUTH packets
                    self.receive(p, addr)
                else:
                    print(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
        else:
            print("| listen thread stopping...")
            
    def makeClient(self, addr, cert):
        c = Node(addr, cert=cert, sendLock=self.sendLock, socket=self.socket)
        c.outboundThread.start()
        return c
        

if __name__ == "__main__":
    from node import S_HOST, S_PORT
    from time import sleep
    s = Server((S_HOST,S_PORT))
    print("\n"*4+"Press <enter> to kill client.")
    s.startThreads()
    input()
    s.isRunning.clear()
    sleep(1)
    print("DONE")