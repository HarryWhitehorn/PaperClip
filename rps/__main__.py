from . import client, server
import threading

def runServer():
    s = server.Server((S_HOST, S_PORT))
    sT = threading.Thread(target=s.mainloop, daemon=True)
    sT.start()
    return s, sT
    
def runClient():
    c = client.Client((C_HOST,C_PORT), (S_HOST, S_PORT))
    return c
    
if __name__ == "__main__":
    from udp import S_HOST, S_PORT, C_HOST, C_PORT
    import time
    print("\n"*4)
    s, sT = runServer()
    time.sleep(1)
    c = runClient()
    c.connect()
    time.sleep(1)
    # x = None
    # x = input("> ")
    # while x != "END":
    #     c.queueDefault(data=x.encode())
    #     x = input("> ")
    c.isRunning = False
    time.sleep(1)
    s.isRunning = False
    time.sleep(1)
    print("END")