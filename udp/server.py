import base64
import json
import socket
import time
from datetime import datetime
from threading import Event, Lock, Thread

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from . import (
    HEARTBEAT_MAX_TIME,
    HEARTBEAT_MIN_TIME,
    MAX_CLIENTS,
    auth,
    bcolors,
    error,
    logger,
    node,
    packet,
)


class Server(node.Node):
    clients: dict[tuple[str, int], node.Node]
    clientsLock: Lock
    clientDeleteEvent: Event
    rsaKey: RSAPrivateKey | None
    heartbeatThread: Thread
    onClientJoin: None
    onClientLeave: None
    maxClients: int

    def __init__(
        self,
        addr,
        maxClients: int = MAX_CLIENTS,
        rsaKey: RSAPrivateKey | None = None,
        onClientJoin=None,
        onClientLeave=None,
        onReceiveData=None,
    ) -> None:
        self.clients = {}
        self.clientsLock = Lock()
        self.clientDeleteEvent = Event()
        self.clientDeleteEvent.set()
        self.rsaKey = rsaKey if rsaKey is not None else auth.generateRsaKey()
        self.onClientJoin = onClientJoin
        self.onClientLeave = onClientLeave
        self.maxClients = maxClients
        s = socket.socket(type=socket.SOCK_DGRAM)
        super().__init__(
            addr,
            cert=auth.generateUserCertificate(self.rsaKey),
            socket=s,
            onReceiveData=onReceiveData,
        )
        self.heartbeatThread = Thread(
            name=f"{self.port}:Heartbeat", target=self.heartbeat, daemon=True
        )
        self.bind(self.addr)

    def receiveAck(self, p: packet.AckPacket, addr: tuple[str, int]) -> None:
        super().receiveAck(p, addr)
        if p.data is not None and not self.getHandshake(
            addr
        ):  # ack has payload & client has not completed handshake => validate handshake
            if not self.validateHandshake(addr, p.data):
                # raise ValueError(f"Local finished value does not match peer finished value {p.data}")
                logger.error(
                    f"Local finished value does not match peer finished value {p.data}"
                )
                self.queueError(
                    addr,
                    major=error.Major.CONNECTION,
                    minor=error.ConnectionErrorCodes.FINISH_INVALID,
                    data=b"Invalid finish.",
                )
            else:
                # print(f"{bcolors.OKGREEN}# Handshake with {addr} successful.{bcolors.ENDC}")
                logger.info(
                    f"{bcolors.OKGREEN}# Handshake with {addr} successful.{bcolors.ENDC}"
                )
                if self.onClientJoin:
                    self.onClientJoin(addr, self.getClientId(addr))

    def receiveAuth(
        self, p: packet.AuthPacket, addr: tuple[str, int]
    ) -> tuple[packet.AuthPacket, tuple[str, int]]:
        if addr not in self.clients:  # new client
            if self.isNotFull():  # check space
                # print(f"{bcolors.WARNING}# Handshake with {addr} starting.{bcolors.ENDC}")
                logger.info(
                    f"{bcolors.WARNING}# Handshake with {addr} starting.{bcolors.ENDC}"
                )
                valid, accountId = self.validateCertificate(p.certificate)
                if not valid:
                    # raise ValueError(f"Invalid peer cert {p.certificate}")
                    logger.error(f"Invalid peer cert {p.certificate}")
                    self.queueError(
                        addr,
                        major=error.Major.CONNECTION,
                        minor=error.ConnectionErrorCodes.CERTIFICATE_INVALID,
                        data=b"Invalid Certificate.",
                    )
                else:
                    self.makeClient(addr, p.certificate, accountId)
                    self.regenerateEcKey(addr)
                    sessionKey = auth.generateSessionKey(
                        self.getEcKey(addr), p.public_key
                    )
                    self.setSessionKey(addr, sessionKey)
                    self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                    self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
            else:
                # print(f"{bcolors.FAIL}# Handshake with {addr} denied due to NO_SPACE.{bcolors.ENDC}")
                logger.warning(
                    f"{bcolors.FAIL}# Handshake with {addr} denied due to NO_SPACE.{bcolors.ENDC}"
                )
                self.queueError(
                    addr,
                    major=error.Major.CONNECTION,
                    minor=error.ConnectionErrorCodes.NO_SPACE,
                    data=b"Server is Full.",
                )
        else:
            sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
        if addr in self.clients:
            if self.getSessionKey(addr) != sessionKey:  # new client sessionKey
                # print(f"{bcolors.WARNING}# Handshake with {addr} reset.{bcolors.ENDC}")
                logger.info(
                    f"{bcolors.WARNING}# Handshake with {addr} reset.{bcolors.ENDC}"
                )
                valid, accountId = self.validateCertificate(p.certificate)
                if not valid:
                    # raise ValueError(f"Invalid peer cert {p.certificate}")
                    logger.warning(f"Invalid peer cert {p.certificate}")
                    self.queueError(
                        addr,
                        major=error.Major.CONNECTION,
                        minor=error.ConnectionErrorCodes.CERTIFICATE_INVALID,
                        data=b"Invalid Certificate.",
                    )
                else:
                    self.regenerateEcKey(addr)
                    # self.clients[addr].cert = p.certificate # shouldn't change
                    sessionKey = auth.generateSessionKey(
                        self.getEcKey(addr), p.public_key
                    )
                    self.setSessionKey(addr, sessionKey)  # make new session key
                    self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                    self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        return (p, addr)

    def queueDisconnect(
        self,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ):
        with self.clientsLock:
            clientAddrs = [addr for addr in self.clients]
        for addr in clientAddrs:
            self.queueError(
                addr,
                flags=flags,
                major=error.Major.DISCONNECT,
                minor=error.DisconnectErrorCodes.SERVER_DISCONNECT,
                data=data,
            )

    def getSessionKey(self, clientAddr: tuple[str, int]) -> bytes | None:
        with self.clientsLock:
            return self.clients[clientAddr].sessionKey

    def setSessionKey(self, clientAddr: tuple[str, int], sessionKey: bytes) -> None:
        with self.clientsLock:
            self.clients[clientAddr].sessionKey = sessionKey

    def getHandshake(self, clientAddr: tuple[str, int]) -> bool:
        with self.clientsLock:
            return self.clients[clientAddr].handshake

    def getSentAckBit(self, clientAddr: tuple[str, int], p: packet.Packet) -> bool:
        with self.clientsLock:
            return self.clients[clientAddr].sentAckBits[p.sequence_id]

    def setSentAckBit(self, clientAddr: tuple[str, int], ackBit: int, v: bool) -> None:
        with self.clientsLock:
            self.clients[clientAddr].sentAckBits[ackBit] = v

    def getSentAckBits(self, clientAddr: tuple[str, int]) -> list[bool]:
        with self.clientsLock:
            return self.clients[clientAddr].sentAckBits

    def getRecvAckBit(self, clientAddr: tuple[str, int], p: packet.Packet) -> bool:
        with self.clientsLock:
            return self.clients[clientAddr].recvAckBits[p.sequence_id]

    def getRecvAckBits(self, clientAddr: tuple[str, int]) -> list[bool]:
        with self.clientsLock:
            return self.clients[clientAddr].recvAckBits

    def setRecvAckBit(self, clientAddr: tuple[str, int], ackBit: int, v: bool) -> None:
        with self.clientsLock:
            self.clients[clientAddr].recvAckBits[ackBit] = v

    def getNewestSeqId(self, clientAddr: tuple[str, int]) -> int:
        with self.clientsLock:
            if clientAddr in self.clients:
                return self.clients[clientAddr].newestSeqId
            else:
                return 0

    def setNewestSeqId(self, clientAddr: tuple[str, int], newSeqId: int) -> None:
        with self.clientsLock:
            if clientAddr in self.clients:
                self.clients[clientAddr].newestSeqId = newSeqId

    def getFragBuffer(
        self, clientAddr: tuple[str, int]
    ) -> dict[int, list[packet.Packet]]:
        with self.clientsLock:
            return self.clients[clientAddr].fragBuffer

    def getEcKey(self, clientAddr: tuple[str, int]) -> auth.ec.EllipticCurvePrivateKey:
        with self.clientsLock:
            return self.clients[clientAddr].ecKey

    def getSequenceId(self, clientAddr: tuple[str, int]) -> int | None:
        with self.clientsLock:
            return (
                self.clients[clientAddr].sequenceId
                if clientAddr in self.clients
                else None
            )

    def getQueue(self, clientAddr: tuple[str, int]) -> node.Queue:
        with self.clientsLock:
            return (
                self.clients[clientAddr].queue
                if clientAddr in self.clients
                else self.queue
            )

    def getSequenceIdLock(self, clientAddr: tuple[str, int]) -> Lock:
        with self.clientsLock:
            return self.clients[clientAddr].sequenceIdLock

    def incrementSequenceId(self, clientAddr: tuple[str, int]) -> None:
        with self.getSequenceIdLock(clientAddr):
            with self.clientsLock:
                self.clients[clientAddr].sequenceId += 1

    def getHeartbeat(self, clientAddr: tuple[str, int]) -> datetime:
        with self.clientsLock:
            return self.clients[clientAddr].heartbeat

    def setHeartbeat(self, clientAddr: tuple[str, int], v: datetime) -> None:
        with self.clientsLock:
            self.clients[clientAddr].heartbeat = v

    def regenerateEcKey(self, clientAddr: tuple[str, int]) -> None:
        with self.clientsLock:
            self.clients[clientAddr].regenerateEcKey()

    def checkClientExists(self, clientAddr: tuple[str, int]) -> bool:
        with self.clientsLock:
            return clientAddr in self.clients

    def validateHandshake(self, clientAddr: tuple[str, int], finished: bytes) -> bool:
        with self.clientsLock:
            return self.clients[clientAddr].validateHandshake(finished)

    def getClientLength(self) -> int:
        with self.clientsLock:
            return len(self.clients)

    def getClientId(self, clientAddr: tuple[str, int]) -> int:
        with self.clientsLock:
            return self.clients[clientAddr].accountId

    def getClientIds(self) -> list[int]:
        with self.clientsLock:
            return [client.id for addr, client in self.clients.items()]

    def isNotFull(self) -> bool:
        with self.clientsLock:
            return len(self.clients) < self.maxClients  # check space

    def isEmpty(self) -> bool:
        with self.clientsLock:
            return len(self.clients) == 0

    def listen(self) -> None:
        logger.info(
            f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}"
        )
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            if p is not None and addr is not None:
                if self.checkClientExists(addr):  # client exists
                    self.setHeartbeat(addr, datetime.now())
                    if self.getHandshake(
                        addr
                    ):  # client handshake complete => allow all packet types
                        self.receive(p, addr)
                    else:
                        if (
                            p.packet_type
                            in (packet.Type.AUTH, packet.Type.ACK, packet.Type.ERROR)
                        ):  # client handshake incomplete => drop all non-AUTH | non-ACK | non-ERROR packets
                            self.receive(p, addr)
                else:
                    if p.packet_type in (
                        packet.Type.AUTH,
                        packet.Type.ERROR,
                    ):  # client not exists => drop all non-AUTH | non-ERROR packets
                        self.receive(p, addr)
                    else:
                        logger.warning(
                            f"{bcolors.WARNING}! {addr} :{bcolors.ENDC} {bcolors.WARNING}{p}{bcolors.ENDC}"
                        )
        else:
            logger.info("| listen thread stopping...")

    def heartbeat(self) -> None:
        while self.isRunning.is_set():
            time.sleep(HEARTBEAT_MIN_TIME)
            with self.clientsLock:
                clients = [k for k in self.clients.keys()]
            for clientAddr in clients:
                heartbeat = self.getHeartbeat(clientAddr)
                delta = (datetime.now() - heartbeat).seconds
                if delta > HEARTBEAT_MAX_TIME:
                    self.removeClient(
                        clientAddr,
                        debugStr=f"due to heartbeat timeout (last contact was {heartbeat})",
                    )
                elif delta > HEARTBEAT_MIN_TIME:
                    self.queueHeartbeat(clientAddr, heartbeat=False)
        else:
            logger.info("| heartbeat thread stopping...")

    def makeClient(
        self, clientAddr: tuple[str, int], cert: auth.x509.Certificate, accountId: int
    ) -> None:
        c = node.Node(
            clientAddr,
            cert=cert,
            accountId=accountId,
            sendLock=self.sendLock,
            socket=self.socket,
        )
        c.outboundThread.start()
        with self.clientsLock:
            self.clients[clientAddr] = c

    def removeClient(self, clientAddr: tuple[str, int], debugStr="") -> None:
        if self.checkClientExists(clientAddr):
            cId = self.getClientId(clientAddr)
            with self.clientsLock:
                logger.info(
                    f"{bcolors.FAIL}# Client {clientAddr} was removed{' '+debugStr}.{bcolors.ENDC}"
                )
                self.clients[clientAddr].isRunning.clear()
                del self.clients[clientAddr]
                if self.onClientLeave:
                    self.onClientLeave(clientAddr, cId)

    # misc
    def startThreads(self) -> None:
        super().startThreads()
        self.heartbeatThread.start()

    def validateCertificate(self, certificate: auth.x509.Certificate) -> bool:
        url = f"http://{self.host}:5000/auth/certificate/validate"
        headers = {"Content-Type": "application/json"}
        certificate = base64.encodebytes(
            auth.getDerFromCertificate(certificate)
        ).decode()
        data = {"certificate": certificate}
        try:
            r = requests.get(url, headers=headers, data=json.dumps(data))
            if r.status_code == 200:
                return r.json()["valid"], r.json()["account-id"]
            else:
                return False
        except:  # noqa: E722
            # Cert server unresponsive
            return False

    def quit(
        self, msg: str = "quit call", e: Exception | None = None
    ) -> Exception | None:
        self.queueDisconnect(data=msg.encode())
        self.queue.join()
        e = super().quit(msg, e)
        if self.heartbeatThread.is_alive:
            self.heartbeatThread.join()
        return e

    def handleDisconnectError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.DisconnectError
    ) -> None:
        match e:
            case error.ServerDisconnectError():
                pass  # should not react to server disconnect
            case error.ClientDisconnectError():
                self.removeClient(addr, "The client has closed")
            case _:
                raise e
