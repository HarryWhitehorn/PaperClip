from node import Node, bcolors
import auth
import packet
# from . import ADDR,PORT

MAX_CLIENTS = 0

class Server(Node):
    clients = {}
    
    def __init__(self, addr):
        super().__init__(addr)
            
    def receiveDefault(self, p, addr):
        super().receiveDefault(p, addr)
        if p.data == "KILL":
            self.isRunning.clear()
            
    def receiveAck(self, p, addr):
        super().receiveAck(p, addr)
        if p.data != None and not self.getHandshake(addr): # ack has payload & client has not completed handshake => validate handshake
            if not self.clients[addr].validateHandshake(p.data):
                raise ValueError(f"Local finished value does not match peer finished value {p.data}")
            
    def receiveAuth(self, p, addr):
        sessionKey = auth.generateSessionKey(self.ecKey, p.publicEc)
        if not addr in self.clients or self.getSessionKey(addr) != sessionKey: # new client or new client sessionKey
            self.clients[addr] = ClientStatus(addr, sessionKey, p.cert)
            self.queueAuth(addr, self.cert, self.ecKey.public_key())
            if not Node.validateCert(p.cert):
                raise ValueError(f"Invalid peer cert {p.cert}")
            self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        return (p,addr)
            
    # def _receiveAuth(self, p, addr):
    #     if self.sessionKey == None:
    #         self.sessionKey = auth.generateSessionKey(self.ecKey, p.publicEc)
    #         finished = auth.generateFinished(self.sessionKey, finishedLabel=b"node finished", messages=b"\x13") # TODO: give appropriate values for label and messages
    #         self.queueAuth(addr, self.cert, self.ecKey.public_key())
    #         self.queueACK(addr, p.sequence_id, finished)
    #             # TODO: send appropriate ACK (& wait for ACK else CRIT FAIL)
    #     return (p,addr)
    
    def getSessionKey(self, clientAddr):
        return self.clients[clientAddr].sessionKey
    
    def getHandshake(self, clientAddr):
        return self.clients[clientAddr]
            
    # def receiveAuth(self, p, addr):
        # return super().receiveAuth(p, addr)
            
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
            print("| listen thread stopping...")
        


class ClientStatus:
    def __init__(self, addr, sessionKey:bytes|None=None, cert=None, handshake=False, heartbeat=None):
        self.addr = addr
        self.sessionKey = sessionKey
        self.cert = cert
        self.handshake = handshake
        self.heartbeat = heartbeat
        
    @property
    def host(self):
        return self.addr[0]
    
    @property
    def port(self):
        return self.addr[1]
    
    def validateHandshake(self, finished):
        self.handshake = Node._generateFinished(self.sessionKey) == finished
        return self.handshake
        

if __name__ == "__main__":
    from node import S_HOST, S_PORT
    from time import sleep
    s = Server((S_HOST,S_PORT))
    print("Press <enter> to kill client.")
    s.startThreads()
    input()
    s.isRunning.clear()
    sleep(1)
    print("DONE")