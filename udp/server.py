from node import Node, bcolors
import auth
import packet
# from . import ADDR,PORT

class ClientStatus:
    def __init__(self, addr, sessionKey:bytes|None=None, cert=None, handshake=False, heartbeat=None, sentAckBits=[None for _ in range(packet.ACK_BITS_SIZE)], recvAckBits=[None for _ in range(packet.ACK_BITS_SIZE)], fragBuffer:dict[int,list[packet.Packet]] = {}):
        self.addr = addr
        self.sessionKey = sessionKey
        self.cert = cert
        self.handshake = handshake
        self.heartbeat = heartbeat
        self.sentAckBits = sentAckBits
        self.recvAckBits = recvAckBits
        self.fragBuffer = fragBuffer
        
    @property
    def host(self):
        return self.addr[0]
    
    @property
    def port(self):
        return self.addr[1]
    
    def validateHandshake(self, finished):
        self.handshake = Node._generateFinished(self.sessionKey) == finished
        return self.handshake
        
class Server(Node):
    clients: dict[tuple[str, int], ClientStatus] = {}
    
    def __init__(self, addr):
        super().__init__(addr)
            
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
                
    def receiveAuth(self, p, addr):
        sessionKey = auth.generateSessionKey(self.ecKey, p.public_key)
        if not addr in self.clients or self.getSessionKey(addr) != sessionKey: # new client or new client sessionKey
            print(f"{bcolors.WARNING}# Handshake with {self.addr} starting/reset.{bcolors.ENDC}")
            self.clients[addr] = ClientStatus(addr, sessionKey, p.certificate)
            self.queueAuth(addr, self.cert, self.ecKey.public_key())
            if not Node.validateCert(p.certificate):
                raise ValueError(f"Invalid peer cert {p.certificate}")
            self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        return (p, addr)
        
    def _testPacket(self, addr):
        flags=packet.lazyFlags(packet.Flag.FRAG)# ,packet.Flag.RELIABLE)
        self.queueDefault(addr, flags=flags, data=b"Hello World To You Too")
    
    def getSessionKey(self, clientAddr):
        return self.clients[clientAddr].sessionKey
    
    def getHandshake(self, clientAddr):
        return self.clients[clientAddr].handshake
    
    def getSentAckBit(self, addr, p):
        return self.clients[addr].sentAckBits[p.sequence_id]
    
    def setSentAckBit(self, clientAddr, ackBit, v:bool):
        self.clients[clientAddr].sentAckBits[ackBit] = v
        
    def getRecvAckBit(self, addr, p):
        return self.clients[addr].recvAckBits[p.sequence_id]
    
    def setRecvAckBit(self, addr, ackBit, v:bool):
        self.clients[addr].recvAckBits[ackBit] = v
        
    def getFragBuffer(self, addr):
        return self.clients[addr].fragBuffer
               
    def listen(self):
        print(f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}")
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            if addr in self.clients: # client exists
                if self.getHandshake(addr): # client handshake complete => allow all packet types
                    self.receive(p, addr)
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