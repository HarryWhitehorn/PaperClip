from threading import Thread

class Lobby:
    members: list[int]
    severThread: Thread
    port: int
    
    def __init__(self, port):
        pass