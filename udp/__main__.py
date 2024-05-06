from . import client, server


def runServer():
    s = server.Server((S_HOST, S_PORT))
    s.startThreads()
    return s


def runClient():
    c = client.Client((C_HOST, C_PORT), (S_HOST, S_PORT))
    c.connect()
    return c


if __name__ == "__main__":
    import time

    from . import C_HOST, C_PORT, S_HOST, S_PORT

    s = runServer()
    time.sleep(1)
    c = runClient()
    time.sleep(1)
    x = None
    x = input("> ")
    while x != "END":
        c.queueDefault(data=x.encode())
        x = input("> ")
    c.isRunning.clear()
    time.sleep(1)
    s.isRunning.clear()
    time.sleep(1)
    print("END")
