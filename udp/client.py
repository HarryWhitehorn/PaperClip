import base64
import json
import socket

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from udp.error import Major, Minor

from . import auth, bcolors, error, logger, node, packet


class Client(node.Node):
    targetAddr: tuple[str, int]
    rsaKey: RSAPrivateKey
    onConnect: None
    onDisconnect: None

    def __init__(
        self,
        addr,
        targetAddr,
        rsaKey: RSAPrivateKey | None = None,
        accountId: int | str | None = None,
        username: str | None = None,
        onConnect=None,
        onDisconnect=None,
        onReceiveData=None,
    ) -> None:
        self.targetAddr = targetAddr
        self.rsaKey = rsaKey if rsaKey is not None else auth.generateRsaKey()
        self.onConnect = onConnect
        self.onDisconnect = onDisconnect
        s = socket.socket(type=socket.SOCK_DGRAM)
        super().__init__(
            addr,
            cert=auth.generateUserCertificate(self.rsaKey, accountId, username),
            accountId=accountId,
            socket=s,
            onReceiveData=onReceiveData,
        )
        self.regenerateEcKey()
        self.bind(self.addr)

    @property
    def targetHost(self) -> str | None:
        return self.targetAddr[0] if self.targetAddr is not None else None

    @property
    def targetPort(self) -> int | None:
        return self.targetAddr[1] if self.targetAddr is not None else None

    def queueDefault(
        self,
        addr: tuple[str, int] = None,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        return super().queueDefault(self.targetAddr, flags=flags, data=data)

    def queueACK(
        self,
        addr: tuple[str, int] = None,
        ackId: int = None,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        return super().queueACK(self.targetAddr, ackId, flags=flags, data=data)

    def queueError(
        self,
        addr: tuple[str, int] = None,
        major: Major | int = 0,
        minor: Minor | int = 0,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        return super().queueError(self.targetAddr, major, minor, flags, data)

    def queueDisconnect(
        self,
        addr: tuple[str, int] = None,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        self.queueError(
            self.targetAddr,
            flags=flags,
            major=error.Major.DISCONNECT,
            minor=error.DisconnectErrorCodes.CLIENT_DISCONNECT,
            data=data,
        )

    def connect(self) -> None:
        try:
            logger.info(
                f"{bcolors.WARNING}# Handshake with {self.targetAddr} starting.{bcolors.ENDC}"
            )
            self.outboundThread.start()
            self.queueAuth(self.targetAddr, self.cert, self.ecKey.public_key())
            authPacket = None
            ackPacket = None
            while True:
                p, addr = self.receivePacket()
                if p is not None:
                    # logic
                    if p.packet_type == packet.Type.AUTH:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        authPacket = p
                        self.sessionKey = auth.generateSessionKey(
                            self.ecKey, p.public_key
                        )
                        if not self.validateCertificate(p.certificate):
                            logger.critical(f"Invalid peer cert {p.certificate}")
                            self.queueError(
                                major=error.Major.CONNECTION,
                                minor=error.ConnectionErrorCodes.CERTIFICATE_INVALID,
                                data=b"Invalid Certificate.",
                            )
                            break
                        self.queueFinished(
                            self.targetAddr, p.sequence_id, self.sessionKey
                        )
                    elif p.packet_type == packet.Type.ACK:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        ackPacket = p
                        self.receiveAck(p, addr)
                    elif p.packet_type == packet.Type.ERROR:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        self.receive(p, addr)
                    else:
                        logger.warning(
                            f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}"
                        )
                    if authPacket is not None and ackPacket is not None:
                        break
                else:
                    # timeout and abort
                    logger.critical("Server not responsive.")
            if self.validateHandshake(p.data):
                # success
                logger.info(
                    f"{bcolors.OKGREEN}Handshake success starting mainloop...{bcolors.ENDC}"
                )
                self.inboundThread.start()
                if self.onConnect:
                    self.onConnect(addr)
            else:
                logger.critical(
                    f"Local finished value {node.Node._generateFinished(self.sessionKey)} does not match peer finished value {ackPacket.data}"
                )
                self.queueError(
                    major=error.Major.CONNECTION,
                    minor=error.ConnectionErrorCodes.FINISH_INVALID,
                    data=b"Invalid finish.",
                )
        except error.PaperClipError as e:
            raise e
        except Exception as e:
            raise e
        else:
            if self.isRunning.is_set():
                self._quit()

    # auth
    def validateCertificate(self, certificate: auth.x509.Certificate) -> bool:
        url = f"http://{self.targetHost}:5000/auth/certificate/validate"
        headers = {"Content-Type": "application/json"}
        certificate = base64.encodebytes(
            auth.getDerFromCertificate(certificate)
        ).decode()
        data = {"certificate": certificate}
        r = requests.get(url, headers=headers, data=json.dumps(data))
        if r.status_code == 200:
            return r.json()["valid"]
        else:
            return False

    # misc
    def quit(self, msg: str = "quit call", e: Exception = None) -> None:
        self.queueDisconnect(data=msg.encode())
        self.queue.join()
        super().quit(msg, e)

    def handleDisconnectError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.DisconnectError
    ) -> None:
        match e:
            case error.ServerDisconnectError():
                self._quit(e)
            case error.ClientDisconnectError():
                pass  # should not react to client disconnect
            case _:
                raise e

    def mainloop(self, onQuit=None) -> None:
        try:
            while self.isRunning.is_set():
                pass
        except KeyboardInterrupt:
            print(f"{bcolors.FAIL}Quitting. Please wait...{bcolors.ENDC}")
        finally:
            if onQuit is None:
                self.quit(e=self.exitError)
            else:
                onQuit(e=self.exitError)
