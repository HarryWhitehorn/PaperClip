from node import Node, S_HOST, S_PORT, C_HOST, C_PORT
import auth
# from queue import Queue
# from . import ADDR,PORT

class Client(Node):
    def __init__(self, addr, targetAddr):
        super().__init__(addr)
        self.targetAddr = targetAddr
    
    @property
    def targetHost(self):
        return self.targetAddr[0]
    
    @property
    def targetPort(self):
        return self.targetAddr[1]
    
    def queueDefault(self, data, flags=[0,0,0,0]):
        return super().queueDefault(self.targetAddr, data, flags)
    
    def queueACK(self, seqId):
        return super().queueACK(self.targetAddr, seqId)
    
    def queueAuth(self, finished=b"\x00"*32):
        return super().queueAuth(self.targetAddr, self.cert, self.ecKey.public_key(), finished)
    
    def receiveAuth(self, p, addr):
        if self.sessionKey == None:
            self.sessionKey = auth.generateSessionKey(self.ecKey, p.publicEc)
            finished = auth.generateFinished(self.sessionKey, finishedLabel=b"node finished", messages=b"\x13") # TODO: give appropriate values for label and messages
            self.queueAuth(finished)
            if p.finished != b"\00"*32:
                assert p.finished == finished
                # TODO: send appropriate ACK (& wait for ACK else CRIT FAIL)
        return (p,addr)
    
if __name__ == "__main__":
    from time import sleep
    c = Client((C_HOST,C_PORT), (S_HOST, S_PORT))
    
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
    c.mainloop()
    # / TESTS
    # killServer()
    # testACK()
    # testAuth()
    # import auth
    # cert = auth.loadCertificate("certOne")
    # ec = auth.generateEcKey()
    # fin = auth.generateFinished()
    c.queueAuth()
    # /
    # print(auth.getDerFromPublicEc(ec.public_key()))
    input()
    c.isRunning.clear()
    sleep(1)
    print("END")
               