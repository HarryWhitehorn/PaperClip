import socket
# from . import ADDR,PORT

S_ADDR = "127.0.0.1"
S_PORT = 2024
BUFFER_SIZE = 1024
C_ADDR = "127.0.0.1"
C_PORT = S_PORT+1

class Client(socket.socket):
    def __init__(self):
        super().__init__(type=socket.SOCK_DGRAM)
        self.sAddr = S_ADDR
        self.sPort = S_PORT
    
    def send(self, message=b"Hello World"):
        print(f"Sending {message} to {self.sAddr}:{self.sPort}")
        self.sendto(message, (self.sAddr,self.sPort))
        
    def receive(self):
        data, addr = self.recvfrom(BUFFER_SIZE)
        print(f"> {addr} : {data}")
        return data, addr
    
    def sendHello(self):
        self.send(b"HELLO")
        return self.validate(self.receive()[0],b"HELLO")
        
    def sendPing(self):
        self.send(b"PING")
        return self.validate(self.receive()[0],b"PONG")
    
    def sendBye(self):
        self.send(b"BYE")
        return self.validate(self.receive()[0],b"BYE")
        
    def validate(self, actual, expected):
        return actual == expected
    
if __name__ == "__main__":
    c = Client()
    c.bind((C_ADDR,C_PORT))
    def _test():
        if c.sendHello():
            if c.sendPing():
                if c.sendBye():
                    pass
                else:
                    print("!BYE FAIL!")
            else:
                print("!PING FAIL!")
        else:
            print("!HELLO FAIL!")
    while True:
        c.send(bytes(input("< "),"UTF-8"))
        data, addr = c.receive()
    # _test()
    # print(c.receive())
    # while True:
    #     c.send(bytes(input(">"),"UTF-8"))
    #     print(c.receive())
               