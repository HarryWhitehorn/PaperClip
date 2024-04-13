from node import Node, S_HOST, S_PORT
# from . import ADDR,PORT

class Server(Node):
    def __init__(self, addr):
        super().__init__(addr)
            
    def receiveDefault(self, p, addr):
        super().receiveDefault(p, addr)
        if p.data == "KILL":
            self.isRunning.clear()
            
    # def listen(self):
    #     print(f"Listening @ {self.socket.getsockname()}")
    #     while self.isRunning.is_set():
    #         # self.receive()
    #         # conn, addr = self.socket.accept()
    #         print(conn, addr)

if __name__ == "__main__":
    from time import sleep
    s = Server((S_HOST,S_PORT))
    s.mainloop()
    input("Press <enter> to kill server.")
    s.isRunning.clear()
    sleep(1)
    print("DONE")