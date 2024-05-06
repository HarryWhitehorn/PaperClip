import threading

from . import client, server


def runServer():
    s = server.Server((S_HOST, S_PORT))
    sT = threading.Thread(target=s.mainloop, daemon=True)
    sT.start()
    return s, sT


def runClient():
    c = client.Client((C_HOST, C_PORT), (S_HOST, S_PORT))
    return c


if __name__ == "__main__":
    import time

    from udp import C_HOST, C_PORT, S_HOST, S_PORT

    print("\n" * 4)
    s, sT = runServer()
    time.sleep(1)
    c = runClient()
    c.connect()
    time.sleep(1)
    c.isRunning = False
    time.sleep(1)
    s.isRunning = False
    time.sleep(1)
    print("END")
