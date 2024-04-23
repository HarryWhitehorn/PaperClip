from threading import Event, Thread
from queue import Queue
import random
import json

from udp.client import Client as UdpClient

from . import bcolors, Choice, Outcome
    
class Client:
    isRunning:bool
    recvQueue: Queue
    udpClient: UdpClient
    score: int
    onReceiveData: None
    
    def __init__(self, addr, targetAddr, rsaKey=None, userId:int|str|None=None, username:str|None=None, onReceiveData=None):
        self.isRunning = True
        self.recvQueue = Queue()
        self.score = 0
        self.onReceiveData = onReceiveData
        self.udpClient = UdpClient(addr, targetAddr, rsaKey=rsaKey, accountId=userId, username=username, onConnect=self.onConnect, onReceiveData=self.receive)
        
    def send(self, addr, data:json):
        self.udpClient.queueDefault(addr, data=self.encodeData(data))
    
    def receive(self, addr, data:bytes):
        self.recvQueue.put((addr,self.decodeData(data)))
        if self.onReceiveData:
            self.onReceiveData(addr, data)
        
    @staticmethod
    def encodeData(data:dict) -> bytes:
        return json.dumps(data).encode()
    
    @staticmethod
    def decodeData(data:bytes) -> dict:
        return json.loads(data.decode())
    
    def connect(self):
        self.udpClient.connect()
        
    def onConnect(self, addr):
        self.mainloop()
        
    def mainloop(self):
        print(f"{bcolors.HEADER}\n\nRock Paper Scissors{bcolors.ENDC}")
        try:
            while self.isRunning:
                choice = None
                while choice == None:
                    try:
                        choice = input("Choice R[0], P[1], S[2]: ")
                        if choice == "q":
                            print(f"{bcolors.FAIL}Quitting. Please wait...{bcolors.ENDC}")
                            self.isRunning = False
                            break
                        choice = int(choice)
                        if not choice in (0,1,2):
                            print(f"{bcolors.FAIL}Invalid choice '{choice}'.{bcolors.ENDC}")
                            choice = None
                    except ValueError:
                        print(f"{bcolors.FAIL}Invalid choice.{bcolors.ENDC}")
                if self.isRunning:
                    self.send(self.udpClient.targetAddr, {"choice":choice})
                    print("Waiting for other player...")
                    addr, data = self.recvQueue.get()
                    match data["outcome"]:
                        case 0:
                            o = f"You {bcolors.FAIL}LOOSE{bcolors.ENDC}. "
                        case 1:
                            o = f"You {bcolors.OKGREEN}WIN{bcolors.ENDC}. "
                        case 2:
                            o = f"You {bcolors.OKCYAN}DRAW{bcolors.ENDC}. "
                        case _:
                            o = ""
                    print(f"\n{o}You Picked {data['choice']}. They picked {data['otherChoice']}.\nThe score is {data['score']['score']}:{data['otherScore']['score']}.")
                    if data["outcome"] == Outcome.WIN:
                        self.score += 1
                    self.recvQueue.task_done()
        finally:
            # send exit
            self.isRunning = False
            self.udpClient.isRunning.clear()

    
if __name__ == "__main__":
    c = Client()
    c.connect()