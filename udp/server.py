from node import Node, S_HOST, S_PORT
# from . import ADDR,PORT

class Server(Node):
    clients = {}
    
    def __init__(self, addr):
        super().__init__(addr)
            
    def receiveDefault(self, p, addr):
        super().receiveDefault(p, addr)
        if p.data == "KILL":
            self.isRunning.clear()
            
    def receiveAuth(self, p, addr):
        return super().receiveAuth(p, addr)
            
    # def listen(self):
    #     print(f"Listening @ {self.socket.getsockname()}")
    #     while self.isRunning.is_set():
    #         # self.receive()
    #         # conn, addr = self.socket.accept()
    #         print(conn, addr)

if __name__ == "__main__":
    from time import sleep
    s = Server((S_HOST,S_PORT))
    print("Press <enter> to kill client.")
    s.mainloop()
    input()
    s.isRunning.clear()
    sleep(1)
    print("DONE")