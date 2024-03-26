import socket
import datetime
# from . import ADDR,PORT

S_ADDR = "127.0.0.1"
S_PORT = 2024
BUFFER_SIZE = 1024

def _now():
    return datetime.datetime.now()

class Sever(socket.socket):
    def __init__(self) -> None:
        super().__init__(type=socket.SOCK_DGRAM)
        self.isRunning = True
        self.clients = {}
    
    def mainloop(self):
        print(f"Listening @ {self.getsockname()}")
        while self.isRunning:
            data, addr = self.recvfrom(BUFFER_SIZE)
            print(f"{addr}: {data}")
            self.receive(data, addr)
            
    def reply(self, message, client):
        self.sendto(message, client)
        
    def receive(self, data, addr):
        match (data):
            case b"HELLO":
                self.clients[addr] = {"last":_now()}
                self.reply(b"HELLO", addr)
            case b"BYE":
                del self.clients[addr]
                self.reply(b"BYE", addr)
            case b"PING":
                self.reply(b"PONG", addr)
            case _:
                print(">>",self.clients)
                self.reply(b"UNKNOWN", addr)

if __name__ == "__main__":
    s = Sever()
    s.bind((S_ADDR,S_PORT))
    s.mainloop()
    