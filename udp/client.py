from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import requests
import socket
import base64
import json
import random

from . import bcolors, node, packet, auth, logger

class Client(node.Node):
    targetAddr: tuple[str,int]
    rsaKey: RSAPrivateKey
    onConnect: None
    onDisconnect: None
    
    def __init__(self, addr, targetAddr, rsaKey:RSAPrivateKey|None=None, userId:int|str|None=None, username:str|None=None, onConnect=None, onDisconnect=None, onReceiveData=None):
        self.targetAddr = targetAddr
        self.rsaKey = rsaKey if rsaKey != None else auth.generateRsaKey()
        self.onConnect = onConnect
        self.onDisconnect = onDisconnect
        s = socket.socket(type=socket.SOCK_DGRAM)
        super().__init__(addr, cert=auth.generateUserCertificate(self.rsaKey, userId, username), socket=s, onReceiveData=onReceiveData)
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
        # print(f"{bcolors.WARNING}# Handshake with {self.targetAddr} starting.{bcolors.ENDC}")
        logger.info(f"{bcolors.WARNING}# Handshake with {self.targetAddr} starting.{bcolors.ENDC}")
        self.outboundThread.start()
        self.queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
        authPacket = None
        ackPacket = None
        while True:
            p, addr = self.receivePacket()
            if p != None:
                #logic
                if p.packet_type == packet.Type.AUTH:
                    # print(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                    logger.info(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                    authPacket = p
                    self.sessionKey = auth.generateSessionKey(self.ecKey, p.public_key)
                    if not self.validateCertificate(p.certificate):
                        # raise ValueError(f"Invalid peer cert {p.certificate}")
                        logger.critical(f"Invalid peer cert {p.certificate}")
                        break
                    self.queueFinished(self.targetAddr, p.sequence_id, self.sessionKey)
                elif p.packet_type == packet.Type.ACK:
                    # print(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                    logger.info(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}")
                    ackPacket = p
                    self.receiveAck(p, addr)
                else:
                    # print(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
                    logger.warning(f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}")
                if authPacket != None and ackPacket != None:
                    break
            else:
                # timeout and abort
                # raise ValueError("Server not responsive.")
                logger.critical("Server not responsive.")
        if self.validateHandshake(p.data):
            # success
            # print(f"{bcolors.OKGREEN}Handshake success starting mainloop...{bcolors.ENDC}")
            logger.info(f"{bcolors.OKGREEN}Handshake success starting mainloop...{bcolors.ENDC}")
            self.inboundThread.start()
            if self.onConnect:
                self.onConnect(addr)
        else:
            # raise ValueError(f"Local finished value {node.Node._generateFinished(self.sessionKey)} does not match peer finished value {ackPacket.data}")
            logger.critical(f"Local finished value {node.Node._generateFinished(self.sessionKey)} does not match peer finished value {ackPacket.data}")
        
    # auth
    def validateCertificate(self, certificate): 
        url = f"http://{self.targetHost}:5000/auth/certificate/validate"
        headers = {"Content-Type":"application/json"}
        certificate = base64.encodebytes(auth.getDerFromCertificate(certificate)).decode()
        data = {"certificate": certificate}
        r = requests.get(url, headers=headers, data=json.dumps(data))
        if r.status_code == 200:
            return r.json()["valid"]
        else:
            return False
    
if __name__ == "__main__":
    from time import sleep
    import os
    
    from . import S_HOST, S_PORT, C_HOST, C_PORT
    
    def testCallback(addr, data):
        pass
        
    portOffset = int(input("offset: "))
    c = Client((C_HOST,C_PORT+portOffset), (S_HOST, S_PORT), onReceiveData=testCallback)
    print("Press <enter> to kill client.")
    c.connect()
    flags=packet.lazyFlags(packet.Flag.RELIABLE, packet.Flag.ENCRYPTED)#, packet.Flag.FRAG)#packet.Flag.RELIABLE, packet.Flag.CHECKSUM, packet.Flag.ENCRYPTED)#, packet.Flag.COMPRESSED)#, packet.Flag.FRAG) #packet.Flag.RELIABLE, packet.Flag.ENCRYPTED)
    with open(r"udp/shakespeare.txt", "rb") as f:
        data = f.read()
    data = data[:len(data)//4]
    for i in range(10):
        c.queueDefault(c.targetAddr, flags=flags, data=f"HelloWorld{i}".encode())
    c.queueDefault(c.targetAddr, data=b"DONE")
    input()
    c.isRunning.clear()
    sleep(1)
    print("END")
               