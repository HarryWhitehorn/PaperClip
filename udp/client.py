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
    
    def queueDefault(self, addr=None, flags=[0 for _ in range(packet.FLAGS_SIZE)], data=None):
        return super().queueDefault(self.targetAddr, flags=flags, data=data)
    
    def queueACK(self, addr=None, ackId=None, flags=[0 for _ in range(packet.FLAGS_SIZE)], data=None):
        return super().queueACK(self.targetAddr, ackId, flags=flags, data=data)
    
    # def queueAuth(self, addr,):
    #     return super().queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
    
    def connect(self):
        self.outboundThread.start()
        self.queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
        authPacket = None
        ackPacket = None
        while True:
            p, addr = self.receivePacket()
            #logic
            if p.packet_type == packet.Type.AUTH:
                print(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                authPacket = p
                self.sessionKey = auth.generateSessionKey(self.ecKey, p.public_key)
                if not Node.validateCert(p.certificate):
                    raise ValueError(f"Invalid peer cert {p.certificate}")
                self.queueFinished(self.targetAddr, p.sequence_id, self.sessionKey)
            elif p.packet_type == packet.Type.ACK:
                print(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                ackPacket = p
                self.receiveAck(p, addr)
            else:
                print(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
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
    portOffset = 0#int(input("offset: "))
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
    c.connect()
    # c.startThreads()
    c.queueDefault(c.targetAddr, flags=packet.lazyFlags(packet.Flag.RELIABLE), data=b"Hello World")
    # /
    # print(auth.getDerFromPublicEc(ec.public_key()))
    input()
    c.isRunning.clear()
    sleep(1)
    print("END")
               