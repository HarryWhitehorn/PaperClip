from node import Node, bcolors
import auth
import packet
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
# from queue import Queue
# from . import ADDR,PORT

class Client(Node):
    targetAddr: tuple[str,int]
    rsaKey: RSAPrivateKey

    def __init__(self, addr, targetAddr, _callback=None):
        self.targetAddr = targetAddr
        self.rsaKey = auth.generateRsaKey()
        super().__init__(addr, cert=auth.generateCertificate(self.rsaKey), _callback=_callback)
        self.regenerateEcKey()
        self.bind(self.addr)
    
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
    
    def connect(self):
        print(f"{bcolors.WARNING}# Handshake with {self.targetAddr} starting.{bcolors.ENDC}")
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
        if self.validateHandshake(p.data):
            # success
            print(f"{bcolors.OKGREEN}Handshake success starting mainloop...{bcolors.ENDC}")
            self.inboundThread.start()
        else:
            raise ValueError(f"Local finished value {Node._generateFinished(self.sessionKey)} does not match peer finished value {ackPacket.data}")
    
if __name__ == "__main__":
    from node import S_HOST, S_PORT, C_HOST, C_PORT
    from time import sleep
    import os
    
    def testCallback(data):
        pass
        
    portOffset = int(input("offset: "))
    c = Client((C_HOST,C_PORT+portOffset), (S_HOST, S_PORT), _callback=testCallback)
    
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
    # input(">")
    flags=packet.lazyFlags(packet.Flag.RELIABLE, packet.Flag.ENCRYPTED)#, packet.Flag.FRAG)#packet.Flag.RELIABLE, packet.Flag.CHECKSUM, packet.Flag.ENCRYPTED)#, packet.Flag.COMPRESSED)#, packet.Flag.FRAG) #packet.Flag.RELIABLE, packet.Flag.ENCRYPTED)
    with open(r"udp/shakespeare.txt", "rb") as f:
        data = f.read()
    data = data[:len(data)//4]
    # c.queueACK(c.targetAddr, c.sequenceId, flags=flags, data=b"Hello World")
    # for _ in range(2*(2**packet.ACK_BITS_SIZE//3)):
    for i in range(10):
        c.queueDefault(c.targetAddr, flags=flags, data=f"HelloWorld{i}".encode())
    c.queueDefault(c.targetAddr, data=b"DONE")
    # /
    # print(auth.getDerFromPublicEc(ec.public_key()))
    input()
    c.isRunning.clear()
    sleep(1)
    print("END")
               