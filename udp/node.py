import time
from datetime import datetime
from queue import Empty, Queue
from socket import SOCK_DGRAM
from socket import socket as Socket
from threading import Event, Lock, Thread, get_ident

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509 import Certificate

from . import (
    QUEUE_TIMEOUT,
    SEND_SLEEP_TIME,
    SOCKET_BUFFER_SIZE,
    SOCKET_TIMEOUT,
    auth,
    bcolors,
    error,
    logger,
    packet,
)

ACK_RESET_SIZE = (2**packet.ACK_BITS_SIZE) // 2


class Node:
    addr: tuple[str, int]
    _sequenceId: int
    sentAckBits = list[bool | None]
    recvAckBits = list[bool | None]
    newestSeqId: int | None
    fragBuffer: dict[int, list[packet.Packet]]
    queue: Queue
    heartbeat: datetime | None
    # id
    cert: Certificate | None
    _accountId: int | None
    # session
    ecKey: EllipticCurvePrivateKey
    sessionKey: bytes | None
    handshake: bool
    # threads
    inboundThread: Thread
    outboundThread: Thread
    sequenceIdLock: Lock
    sendLock: Lock
    isRunning: Event
    # socket
    socket: Socket | None
    # callback
    onReceiveData: None
    # exitCode
    exitError: error.PaperClipError | None

    def __init__(
        self,
        addr: tuple[str, int],
        cert: Certificate | None = None,
        accountId: int | None = None,
        sendLock: Lock = Lock(),
        socket: Socket | None = Socket(type=SOCK_DGRAM),
        onReceiveData: None = None,
    ) -> None:
        self.addr = addr
        self.sequenceId = 0
        self.sentAckBits = [None for _ in range(2**packet.ACK_BITS_SIZE)]
        self.recvAckBits = [None for _ in range(2**packet.ACK_BITS_SIZE)]
        self.newestSeqId = 0
        self.fragBuffer = {}
        self.queue = Queue()
        # id
        self.cert = cert
        self.accountId = accountId
        # session
        self.sessionKey = None
        self.handshake = False
        # threads
        self.inboundThread = Thread(
            name=f"{self.port}:Inbound", target=self.listen, daemon=True
        )
        self.outboundThread = Thread(
            name=f"{self.port}:Outbound", target=self.sendQueue, daemon=True
        )
        self.sequenceIdLock = Lock()
        self.sendLock = sendLock
        self.isRunning = Event()
        self.isRunning.set()
        # socket
        self.socket = socket
        self.socket.settimeout(SOCKET_TIMEOUT)
        # callback
        self.onReceiveData = onReceiveData
        # exit
        self.exitError = None

    def bind(self, addr):
        self.socket.bind(addr)

    # properties
    @property
    def host(self) -> str:
        return self.addr[0]

    @property
    def port(self) -> int:
        return self.addr[1]

    @property
    def sequenceId(self) -> int:
        return self._sequenceId

    @sequenceId.setter
    def sequenceId(self, v: int) -> None:
        self._sequenceId = v % 2**packet.SEQUENCE_ID_SIZE

    def incrementSequenceId(self, addr: tuple[str, int]) -> None:
        with self.getSequenceIdLock(addr):
            self.sequenceId += 1

    @property
    def accountId(self) -> int:
        return self._accountId

    @accountId.setter
    def accountId(self, v: int | str | None) -> None:
        try:
            self._accountId = int(v)
        except ValueError:
            self._accountId = v
        except TypeError:
            self._accountId = None

    def getSentAckBit(self, addr: tuple[str, int], p: packet.Packet) -> bool | None:
        return self.sentAckBits[p.sequence_id]

    def setSentAckBit(self, addr: tuple[str, int], ackBit: int, v: bool) -> None:
        self.sentAckBits[ackBit] = v

    def getSentAckBits(self, addr: tuple[str, int]) -> list[bool | None]:
        return self.sentAckBits

    def getRecvAckBit(self, addr: tuple[str, int], p: packet.Packet) -> bool | None:
        return self.recvAckBits[p.sequence_id]

    def getRecvAckBits(self, addr: tuple[str, int]) -> list[bool | None]:
        return self.recvAckBits

    def setRecvAckBit(self, addr: tuple[str, int], ackBit: int, v: bool) -> None:
        self.recvAckBits[ackBit] = v

    def resetRecvAckBits(self, addr: tuple[str, int]) -> None:
        recvAckBits = self.getRecvAckBits(addr)
        newestSeqId = self.getNewestSeqId(addr)
        pointer = (newestSeqId - ACK_RESET_SIZE) % 2**packet.ACK_BITS_SIZE
        counter = 0
        while counter != pointer:
            recvAckBits[(newestSeqId + 1 + counter) % 2**packet.ACK_BITS_SIZE] = None
            counter += 1

    def getNewestSeqId(self, addr: tuple[str, int]) -> int:
        return self.newestSeqId

    def setNewestSeqId(self, addr: tuple[str, int], newestSeqId: int) -> None:
        self.newestSeqId = newestSeqId

    @staticmethod
    def getNewerSeqId(currentSeqId: int, newSeqId: int) -> int:
        currentDiff = (newSeqId - currentSeqId) % (2**packet.SEQUENCE_ID_SIZE)
        newDiff = (currentSeqId - newSeqId) % (2**packet.SEQUENCE_ID_SIZE)
        if newDiff < currentDiff:
            return currentSeqId
        else:
            return newSeqId

    def getSessionKey(self, addr: tuple[str, int]) -> int:
        return self.sessionKey

    def getHandshake(self, addr: tuple[str, int]) -> bool:
        return self.handshake

    def getFragBuffer(self, addr: tuple[str, int]) -> dict[int, list[packet.Packet]]:
        return self.fragBuffer

    def getSequenceId(self, addr: tuple[str, int]) -> int:
        return self.sequenceId

    def getSequenceIdLock(self, addr: tuple[str, int]) -> Lock:
        return self.sequenceIdLock

    def getQueue(self, addr: tuple[str, int]) -> Queue:
        return self.queue

    def getHeartbeat(self, addr: tuple[str, int]) -> datetime:
        return self.heartbeat

    def setHeartbeat(self, addr: tuple[str, int], v: datetime) -> None:
        self.heartbeat = v

    def regenerateEcKey(self) -> None:
        self.ecKey = auth.generateEcKey()

    # sends
    def sendPacket(self, addr: tuple[str, int], p: packet.Packet) -> None:
        with self.sendLock:
            try:
                self.socket.sendto(p.pack(p), (addr[0], addr[1]))
                logger.info(
                    f"{bcolors.OKBLUE}> {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                )
            except error.PacketError as e:
                logger.error(
                    f"{bcolors.FAIL}# > {bcolors.ENDC}{bcolors.OKBLUE}{addr} :{bcolors.ENDC} {bcolors.FAIL}{type(e).__name__}:{e.args[0] if len(e.args) > 0 else ''}{p}{bcolors.ENDC}"
                )

    def sendQueue(self) -> None:
        while self.isRunning.is_set():
            try:
                addr, p = self.queue.get(timeout=QUEUE_TIMEOUT)
                if p.flags[packet.Flag.RELIABLE.value]:
                    if self.getSentAckBit(addr, p):
                        continue
                    else:
                        self.sendPacket(addr, p)
                        self.queue.task_done()
                        self.queue.put((addr, p))
                else:
                    self.sendPacket(addr, p)
                    self.queue.task_done()
                time.sleep(SEND_SLEEP_TIME)
            except Empty:
                pass  # check still running
        else:
            logger.info("| sendQueue thread stopping...")

    def queuePacket(self, addr: tuple[str, int], p: packet.Packet) -> None:
        if p.flags[packet.Flag.RELIABLE.value]:
            self.setSentAckBit(addr, p.sequence_id, False)
        if p.flags[packet.Flag.CHECKSUM.value]:
            p.setChecksum()
        if p.flags[packet.Flag.COMPRESSED.value]:
            p.compressData()
        if p.flags[packet.Flag.ENCRYPTED.value]:
            p.encryptData(self.getSessionKey(addr))
        if p.flags[packet.Flag.FRAG.value]:
            frags = p.fragment()
            for frag in frags:
                self.getQueue(addr).put((addr, frag))
        else:
            self.getQueue(addr).put((addr, p))

    def queueDefault(
        self,
        addr: tuple[str, int],
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        p = packet.Packet(sequence_id=self.getSequenceId(addr), flags=flags, data=data)
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)

    def queueACK(
        self,
        addr: tuple[str, int],
        ackId: int,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        ack_bits = self.packRecvAckBits(self.getRecvAckBits(addr), ackId)
        p = packet.AckPacket(
            sequence_id=self.getSequenceId(addr),
            flags=flags,
            ack_id=ackId,
            ack_bits=ack_bits,
            data=data,
        )
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)

    def queueAuth(
        self,
        addr: tuple[str, int],
        cert: Certificate,
        publicEc: auth.ec.EllipticCurvePublicKey,
    ) -> None:
        p = packet.AuthPacket(
            sequence_id=self.getSequenceId(addr), certificate=cert, public_key=publicEc
        )
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)

    def queueFinished(
        self, addr: tuple[str, int], seqId: int, sessionKey: bytes
    ) -> None:
        finished = Node._generateFinished(sessionKey)
        self.queueACK(addr, seqId, data=finished)

    @staticmethod
    def _generateFinished(sessionKey: bytes) -> bytes:
        return auth.generateFinished(
            sessionKey, finishedLabel=b"node finished", messages=b"\x13"
        )

    def queueHeartbeat(
        self,
        addr: tuple[str, int],
        heartbeat: bool,
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        p = packet.HeartbeatPacket(
            sequence_id=self.getSequenceId(addr),
            flags=flags,
            heartbeat=heartbeat,
            data=data,
        )
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)

    def queueError(
        self,
        addr: tuple[str, int],
        major: error.Major | int,
        minor: error.Minor | int,
        flags: list[int] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        sId = self.getSequenceId(addr)
        p = packet.ErrorPacket(
            sequence_id=sId if sId is not None else 0,
            flags=flags,
            major=major,
            minor=minor,
            data=data,
        )
        if sId is not None:
            self.incrementSequenceId(addr)
        self.queuePacket(addr, p)

    def queueDisconnect(
        self,
        addr: tuple[str, int],
        flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        self.queueError(
            addr,
            flags=flags,
            major=error.Major.DISCONNECT,
            minor=error.DisconnectErrorCodes.DISCONNECT,
            data=data,
        )

    # receives
    def receivePacket(
        self,
    ) -> tuple[packet.Packet, tuple[str, int]] | tuple[None, None]:
        try:
            data, addr = self.socket.recvfrom(SOCKET_BUFFER_SIZE)
            try:
                p = packet.unpack(data)
                return p, addr
            except error.PacketError as e:
                logger.error(
                    f"{bcolors.FAIL}# < {bcolors.ENDC}{bcolors.OKBLUE}{addr} :{bcolors.ENDC} {bcolors.FAIL}{type(e).__name__}:{e.args[0] if len(e.args) > 0 else ''}{p}{bcolors.ENDC}"
                )
                major, minor = error.getErrorCod(e)
                self.queueError(addr, major, minor)
                return None, None
        except ConnectionResetError:
            return None, None
        except TimeoutError:
            return None, None

    def receive(
        self, p: packet.Packet, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]] | None:
        if p is not None:
            if self.handleFlags(p, addr):
                match p.packet_type:
                    case packet.Type.DEFAULT:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        return self.receiveDefault(p, addr)
                    case packet.Type.ACK:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        return self.receiveAck(p, addr)
                    case packet.Type.AUTH:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        return self.receiveAuth(p, addr)
                    case packet.Type.HEARTBEAT:
                        logger.info(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}"
                        )
                        return self.receiveHeartbeat(p, addr)
                    case packet.Type.ERROR:
                        logger.warning(
                            f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.FAIL}{p}{bcolors.ENDC}"
                        )
                        try:
                            return self.receiveError(p, addr)
                        except error.PaperClipError as e:
                            self.handleError(p, addr, e)
                    case _:
                        logger.warning(
                            f"Unknown packet type '{p.packet_type}' for packet {p}"
                        )
                        self.queueError(
                            addr,
                            major=error.Major.PACKET,
                            minor=error.PacketErrorCodes.PACKET_TYPE,
                            data=p.sequence_id,
                        )

    def receiveDefault(
        self, p: packet.Packet, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]]:
        self.setNewestSeqId(
            addr, self.getNewerSeqId(self.getNewestSeqId(addr), p.sequence_id)
        )
        if self.onReceiveData:
            self.onReceiveData(addr, p.data)
        return (p, addr)

    def receiveAck(
        self, p: packet.AckPacket, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]]:
        self.setNewestSeqId(
            addr, self.getNewerSeqId(self.getNewestSeqId(addr), p.sequence_id)
        )
        self.setSentAckBit(addr, p.ack_id, True)
        # set all bits from ack bits to true (to mitigate lost ack)
        for i, j in enumerate(
            range(p.ack_id - 1, p.ack_id - 1 - packet.ACK_BITS_SIZE, -1)
        ):
            if p.ack_bits[i]:
                self.setSentAckBit(addr, j, True)
        return (p, addr)

    def receiveAuth(
        self, p: packet.AuthPacket, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]]:
        raise NotImplementedError(
            "Node should not receive auth. A child class must overwrite."
        )
        return (p, addr)

    def receiveHeartbeat(
        self, p: packet.HeartbeatPacket, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]]:
        if not p.heartbeat:
            self.queueHeartbeat(addr, heartbeat=True)
            pass
        return (p, addr)

    def receiveError(self, p: packet.ErrorPacket, addr: tuple[str, int]) -> None:
        raise error.getError(p.major, p.minor)(p.data)

    def listen(self) -> None:
        logger.info(
            f"{bcolors.HEADER}Listening @ {self.socket.getsockname()}{bcolors.ENDC}"
        )
        while self.isRunning.is_set():
            p, addr = self.receivePacket()
            self.receive(p, addr)
        else:
            logger.info("| listen thread stopping...")

    # flags handle
    def handleFlags(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        # defrag -> decrypt -> decompress -> validate checksum -> reliable
        if self.handleFrag(p, addr):
            return False
        else:
            self.handleEncrypted(p, addr)
            self.handleCompressed(p, addr)
            self.handleChecksum(p, addr)
            self.handleReliable(p, addr)
            return True

    def handleReliable(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.RELIABLE.value]:
            self.setNewestSeqId(
                addr, self.getNewerSeqId(self.getNewestSeqId(addr), p.sequence_id)
            )
            self.setRecvAckBit(addr, p.sequence_id, True)
            self.resetRecvAckBits(addr)
            self.queueACK(addr, p.sequence_id)
            return True
        else:
            return False

    def handleFrag(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.FRAG.value]:
            logger.info(
                f"\t{bcolors.OKBLUE}< {addr} :{bcolors.ENDC}{bcolors.WARNING} FRAG {p.fragment_id}/{p.fragment_number} {p}{bcolors.ENDC}"
            )
            if p.sequence_id not in self.getFragBuffer(addr):
                self.getFragBuffer(addr)[p.sequence_id] = [
                    None for _ in range(p.fragment_number)
                ]
            self.getFragBuffer(addr)[p.sequence_id][p.fragment_id] = p
            if all(self.getFragBuffer(addr)[p.sequence_id]):
                defrag = p.defragment(self.getFragBuffer(addr)[p.sequence_id])
                del self.getFragBuffer(addr)[p.sequence_id]
                self.receive(defrag, addr)
            return True
        else:
            return False

    def handleCompressed(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.COMPRESSED.value]:
            p.decompressData()
            return True
        else:
            return False

    def handleEncrypted(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.ENCRYPTED.value]:
            p.decryptData(self.getSessionKey(addr))
            return True
        else:
            return False

    def handleChecksum(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.CHECKSUM.value]:
            if not p.validateChecksum():
                logger.warning(f"\tInvalid checksum: {p}")
            else:
                logger.info(f"\tValid checksum: {p}")
            return True
        else:
            return False

    # error handle
    def handleError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.PaperClipError
    ) -> None:
        match e:
            case error.ConnectionError():
                self.handleConnectionError(p, addr, e)
            case error.DisconnectError():
                self.handleDisconnectError(p, addr, e)
            case error.PacketError():
                self.handlePacketError(p, addr, e)
            case _:
                raise e

    def handleConnectionError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.ConnectionError
    ) -> None:
        match e:
            case error.NoSpaceError():
                return self.quit("no server space", e)
            case error.CertificateInvalidError():
                return self.quit("invalid certificate", e)
            case error.FinishInvalidError():
                return self.quit("invalid finish", e)
            case _:
                raise e

    def handleDisconnectError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.DisconnectError
    ) -> None:
        match e:
            case error.ServerDisconnectError:
                pass  # overwrite
            case error.ClientDisconnectError:
                pass  # overwrite
            case _:
                raise e

    def handlePacketError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.PacketError
    ) -> None:
        match e:
            case error.VersionError():
                pass
            case error.PacketTypeError():
                pass
            case error.FlagsError():
                pass
            case error.SequenceIdError():
                pass
            case error.FragmentIdError():
                pass
            case error.FragmentNumberError():
                pass
            case error.InitVectorError():
                pass
            case error.CompressionError():
                pass
            case error.ChecksumError():
                pass
            case _:
                raise e

    # util
    @staticmethod
    def packRecvAckBits(recvAckBits: list[bool], ackId: int) -> list[bool | None]:
        return [
            recvAckBits[i % 2**packet.ACK_BITS_SIZE]
            for i in range(ackId - 1, ackId - 1 - packet.ACK_BITS_SIZE, -1)
        ]

    # misc
    def startThreads(self) -> None:
        self.inboundThread.start()
        self.outboundThread.start()

    def validateCertificate(self, certificate: Certificate) -> bool:
        # overwrite
        return True

    def validateHandshake(self, finished: bytes) -> bool:
        self.handshake = Node._generateFinished(self.sessionKey) == finished
        return self.handshake

    def quit(self, msg: str = "quit call", e: Exception = None) -> None:
        logMsg = f"{bcolors.FAIL}# Quitting due to {msg}.{bcolors.ENDC}"
        if e is not None:
            logger.critical(logMsg)
        else:
            logger.info(logMsg)
        self.isRunning.clear()
        if self.inboundThread.is_alive() and get_ident() != self.inboundThread.ident:
            self.inboundThread.join()
        if self.outboundThread.is_alive() and get_ident() != self.outboundThread.ident:
            self.outboundThread.join()
        self.socket.close()
        logger.info(f"{bcolors.FAIL}# Quit finished.{bcolors.ENDC}")
        if e is not None:
            self.exitError = e
            if get_ident() in (self.inboundThread.ident, self.outboundThread.ident):
                pass
            else:
                raise e

    def _quit(self, e: Exception = None) -> None:
        self.exitError = e
        self.isRunning.clear()
