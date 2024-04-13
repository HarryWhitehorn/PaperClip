from node import Node, S_HOST, S_PORT, C_HOST, C_PORT
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
    
if __name__ == "__main__":
    from time import sleep
    c = Client((C_HOST,C_PORT), (S_HOST, S_PORT))
    c.mainloop()
    
    def killServer():
        print("---START killServer---")
        c.queueDefault("KILL", [1,0,0,0])
        print("---END killServer---")
    
    def testACK(n=4):
        print("---START testACK---")
        for i in range(n):
            c.queueDefault(f"Hello World {i}", [1,0,0,0])
        print("---END testACK---")
        
    testACK()
    # killServer()
    input("Press <enter> to kill client.")
    c.isRunning.clear()
    sleep(1)
    print("END")
               