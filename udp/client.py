from node import Node, bcolors
import auth
import packet
# from queue import Queue
# from . import ADDR,PORT

class Client(Node):
    def __init__(self, addr, targetAddr):
        super().__init__(addr)
        self.targetAddr = targetAddr
    
    @property
    def targetHost(self):
        return self.targetAddr[0] if self.targetAddr != None else None
    
    @property
    def targetPort(self):
        return self.targetAddr[1] if self.targetAddr != None else None
    
    def queueDefault(self, addr, data, flags=[0,0,0,0]):
        return super().queueDefault(self.targetAddr, data, flags)
    
    def queueACK(self, addr, seqId, data=None):
        return super().queueACK(self.targetAddr, seqId, data)
    
    # def queueAuth(self, addr,):
    #     return super().queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
    
    def connect(self):
        self.outboundThread.start()
        self.queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
        authPacket = None
        ackPacket = None
        finished = None
        while True:
            p, addr = self.receivePacket()
            if p.packet_type == packet.Type.AUTH:
                authPacket = p
                self.sessionKey = auth.generateSessionKey(self.ecKey, p.publicEc)
                if not Node.validateCert(p.cert):
                    raise ValueError(f"Invalid peer cert {p.cert}")
                self.queueFinished(self.targetAddr, p.sequence_id, self.sessionKey)
            elif p.packet_type == packet.Type.ACK:
                ackPacket = p
                self.receiveAck(p, addr)
            if authPacket != None and ackPacket != None:
                break
        if Node._generateFinished(self.sessionKey) == ackPacket.data:
            # success
            print(f"{bcolors.OKGREEN}Handshake success starting mainloop...{bcolors.ENDC}")
            self.inboundThread.start()
        else:
            raise ValueError(f"Local finished value {Node._generateFinished(self.sessionKey)} does not match peer finished value {ackPacket.data}")
    
if __name__ == "__main__":
    from node import S_HOST, S_PORT, C_HOST, C_PORT
    from time import sleep
    portOffset = int(input("offset: "))
    c = Client((C_HOST,C_PORT+portOffset), (S_HOST, S_PORT))
    
    def killServer():
        print("---START killServer---")
        c.queueDefault("KILL", [1,0,0,0])
        print("---END killServer---")
    
    def testAck(n=4):
        print("---START testACK---")
        for i in range(n):
            c.queueDefault(f"Hello World {i}", [1,0,0,0])
        print("---END testACK---")
        
    def testAuth():
        print("---Starting testAuth---")
        c.queueAuth()
        print("---END testAuth---")
    
    print("Press <enter> to kill client.")
    # c.mainloop()
    
    # / TESTS
    # killServer()
    # testACK()
    # testAuth()
    # import auth
    # cert = auth.loadCertificate("certOne")
    # ec = auth.generateEcKey()
    # fin = auth.generateFinished()
    # c.queueAuth()
    # c.connect()
    c.startThreads()
    c.queueDefault(c.targetAddr, b"Hello World")
    # /
    # print(auth.getDerFromPublicEc(ec.public_key()))
    input()
    c.isRunning.clear()
    sleep(1)
    print("END")
               