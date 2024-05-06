import json
from queue import Empty, Queue
from threading import Thread

import udp.error as error
from inputimeout import TimeoutOccurred, inputimeout
from udp.auth import rsa
from udp.client import Client as UdpClient
from udp.packet import Flag, lazyFlags

from . import QUEUE_TIMEOUT, Outcome, bcolors


class Client:
    isRunning: bool
    recvQueue: Queue
    score: int
    onReceiveData: None
    gameThread: Thread
    udpClient: UdpClient

    def __init__(
        self,
        addr: tuple[str, int],
        targetAddr: tuple[str, int],
        rsaKey: rsa.RSAPrivateKey|None = None,
        userId: int | str | None = None,
        username: str | None = None,
        onReceiveData=None,
    ) -> None:
        self.isRunning = True
        self.recvQueue = Queue()
        self.score = 0
        self.onReceiveData = onReceiveData
        self.gameThread = Thread(
            name=f"{addr[1]}:Gameloop", target=self.gameloop, daemon=True
        )
        self.udpClient = UdpClient(
            addr,
            targetAddr,
            rsaKey=rsaKey,
            accountId=userId,
            username=username,
            onConnect=self.onConnect,
            onReceiveData=self.receive,
        )

    def send(self, addr: tuple[str, int], data: json) -> None:
        self.udpClient.queueDefault(
            addr, flags=lazyFlags(Flag.RELIABLE), data=self.encodeData(data)
        )

    def receive(self, addr: tuple[str, int], data: bytes):
        self.recvQueue.put((addr, self.decodeData(data)))
        if self.onReceiveData:
            self.onReceiveData(addr, data)

    @staticmethod
    def encodeData(data: dict) -> bytes:
        return json.dumps(data).encode()

    @staticmethod
    def decodeData(data: bytes) -> dict:
        return json.loads(data.decode())

    def connect(self) -> None:
        try:
            self.udpClient.connect()
        except error.PaperClipError as e:
            match e:
                case error.NoSpaceError():
                    print(
                        f"{bcolors.FAIL}Failed to join server due to {error.ConnectionErrorCodes.NO_SPACE.name}: {e.args[0]}{bcolors.ENDC}"
                    )
                case error.CertificateInvalidError():
                    print(
                        f"{bcolors.FAIL}Failed to join server due to {error.ConnectionErrorCodes.CERTIFICATE_INVALID.name}: {e.args[0]}{bcolors.ENDC}"
                    )
                case error.FinishInvalidError():
                    print(
                        f"{bcolors.FAIL}Failed to join server due to {error.ConnectionErrorCodes.FINISH_INVALID.name}: {e.args[0]}{bcolors.ENDC}"
                    )
                case _:
                    raise e

    def onConnect(self, addr: tuple[str, int]) -> None:
        self.gameThread.start()
        try:
            self.udpClient.mainloop(self.quit)
        except error.PaperClipError as e:
            match e:
                case error.ServerDisconnectError():
                    print(
                        f"{bcolors.FAIL}Server connection terminated due to {error.DisconnectErrorCodes.SERVER_DISCONNECT.name}: {e.args[0]}\nPlease wait while connection closes gracefully...{bcolors.ENDC}"
                    )
                case _:
                    raise e
        if self.gameThread.is_alive():
            self.gameThread.join()
        return None

    def gameloop(self) -> None:
        print(f"{bcolors.HEADER}\n\nRock Paper Scissors{bcolors.ENDC}")
        try:
            while self.isRunning:
                choice = None
                print("Choice R[0], P[1], S[2]: ")
                while choice is None:
                    try:
                        choice = inputimeout("", timeout=10).strip()
                        if choice == "q":
                            print(
                                f"{bcolors.FAIL}Quitting. Please wait...{bcolors.ENDC}"
                            )
                            self.isRunning = False
                            break
                        choice = int(choice)
                        if choice not in (0, 1, 2):
                            print(
                                f"{bcolors.FAIL}Invalid choice '{choice}'.{bcolors.ENDC}"
                            )
                            choice = None
                    except ValueError:
                        print(f"{bcolors.FAIL}Invalid choice.{bcolors.ENDC}")
                        choice = None
                    except KeyboardInterrupt:
                        print(f"{bcolors.FAIL}Quitting. Please wait...{bcolors.ENDC}")
                        self.isRunning = False
                        break
                    except TimeoutOccurred:
                        if not self.isRunning:
                            break
                if self.isRunning:
                    self.send(self.udpClient.targetAddr, {"choice": choice})
                    print("Waiting for other player...")
                    while self.isRunning:
                        try:
                            addr, data = self.recvQueue.get(QUEUE_TIMEOUT)
                            break
                        except Empty:
                            pass  # check still running
                    if self.isRunning:
                        match data["outcome"]:
                            case 0:
                                o = f"You {bcolors.FAIL}LOOSE{bcolors.ENDC}. "
                            case 1:
                                o = f"You {bcolors.OKGREEN}WIN{bcolors.ENDC}. "
                            case 2:
                                o = f"You {bcolors.OKCYAN}DRAW{bcolors.ENDC}. "
                            case _:
                                o = ""
                        print(
                            f"\n{o}You Picked {data['choice']}. They picked {data['otherChoice']}.\nThe score is {data['score']['score']}:{data['otherScore']['score']}."
                        )
                        if data["outcome"] == Outcome.WIN:
                            self.score += 1
                        self.recvQueue.task_done()
        finally:
            self.udpClient._quit()

    def quit(self, msg: str = "quit call", e: Exception | None = None) -> None:
        self.isRunning = False
        self.udpClient.quit(msg, e)
