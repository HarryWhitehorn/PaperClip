# 9.3 Package

## 9.3.1 udp

### 9.3.1.1 __init__.py

```python
# udp.__init__
import logging
import os
import sys

import dotenv

__version__ = 0

dotenv.load_dotenv(".env")
S_HOST = os.environ.get("S_HOST")
S_PORT = int(os.environ.get("S_PORT"))
C_HOST = os.environ.get("C_HOST")
C_PORT = int(os.environ.get("C_PORT"))
# node
SOCKET_BUFFER_SIZE = int(os.environ.get("SOCKET_BUFFER_SIZE"))
SEND_SLEEP_TIME = float(os.environ.get("SEND_SLEEP_TIME"))
QUEUE_TIMEOUT = int(os.environ.get("QUEUE_TIMEOUT"))
SOCKET_TIMEOUT = int(os.environ.get("SOCKET_TIMEOUT"))
# server
HEARTBEAT_MAX_TIME = int(os.environ.get("HEARTBEAT_MAX_TIME"))
HEARTBEAT_MIN_TIME = int(os.environ.get("HEARTBEAT_MIN_TIME"))
MAX_CLIENTS = (
    int(os.environ.get("MAX_CLIENTS"))
    if os.environ.get("MAX_CLIENTS") is not None
    else float("inf")
)
# auth
ORG_NAME = os.environ.get("ORG_NAME")
COMMON_NAME = os.environ.get("COMMON_NAME")
# utils
MAX_FRAGMENT_SIZE = int(os.environ.get("MAX_FRAGMENT_SIZE"))


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class ColorFilter(logging.Filter):
    colorCodes = [
        getattr(bcolors, attr) for attr in dir(bcolors) if not attr.startswith("__")
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        for color in self.colorCodes:
            record.msg = record.msg.replace(color, "")
        return True


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

printHandler = logging.StreamHandler(sys.stdout)
printHandler.setLevel(logging.INFO)
printHandler.setFormatter(
    logging.Formatter(f"{bcolors.OKBLUE}%(threadName)s{bcolors.ENDC} - %(message)s")
)
logger.addHandler(printHandler)

fileHandler = logging.FileHandler("paperclip.log")
fileHandler.setLevel(logging.DEBUG)
fileHandler.addFilter(ColorFilter())
fileHandler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
)
logger.addHandler(fileHandler)
```

### 9.3.1.2 __main__.py

```python
# upd.__main__
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
```

### 9.3.1.3 auth.py

```python
# udp.auth
import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as aPadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

from . import COMMON_NAME, ORG_NAME


def generateRsaKey() -> rsa.RSAPrivateKey:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key


def getDerFromRsaPrivate(key: rsa.RSAPrivateKey, password: bytes) -> bytes:
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    return der


def getRsaPrivateFromDer(data: bytes, password: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_der_private_key(data, password=password)
    return key


def getDerFromRsaPublic(key: rsa.RSAPublicKey) -> bytes:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der


def getRsaPublicFromDer(data: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_der_public_key(data)
    return key


def generateUserCertificate(
    key, userId: int | str | None = None, username: str | None = None
) -> x509.Certificate:
    name = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
    ]
    if userId is not None:
        name.append(x509.NameAttribute(NameOID.USER_ID, str(userId)))
    if username is not None:
        name.append(x509.NameAttribute(NameOID.PSEUDONYM, username))
    subject = issuer = x509.Name(name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    return cert


def getUserCertificateAttributes(certificate: x509.Certificate) -> list:
    accountId = certificate.subject.get_attributes_for_oid(NameOID.USER_ID)
    accountId = accountId[0].value if len(accountId) > 0 else None
    username = certificate.subject.get_attributes_for_oid(NameOID.PSEUDONYM)
    username = username[0].value if len(username) > 0 else None
    return {"account-id": accountId, "username": username}


def validateCertificate(
    certificate: x509.Certificate, publicKey: rsa.RSAPublicKey
) -> bool:
    # period
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
        return False
    # signature
    try:
        publicKey.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            aPadding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False
    return True


def generateEcKey() -> ec.EllipticCurvePrivateKey:
    key = ec.generate_private_key(ec.SECP384R1())
    return key


def getDerFromPublicEc(publicKey: ec.EllipticCurvePublicKey) -> bytes:
    ecDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ecDer


def getPublicEcFromDer(publicKeyDer: bytes) -> ec.EllipticCurvePublicKey:
    ec_ = serialization.load_der_public_key(publicKeyDer)
    return ec_


def getDerFromCertificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def getCertificateFromDer(certificateDer: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(certificateDer)


def generateSessionKey(
    localKey: ec.EllipticCurvePrivateKey, peerKey: ec.EllipticCurvePublicKey
) -> bytes:
    sessionSecret = localKey.exchange(ec.ECDH(), peerKey)
    sessionKey = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data"
    ).derive(sessionSecret)
    return sessionKey


def encryptBytes(cipher: Cipher, rawBytes: bytes, autoPad=True) -> bytes:
    if autoPad:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        rawBytes = padder.update(rawBytes) + padder.finalize()
    encryptor = cipher.encryptor()
    encryptedBytes = encryptor.update(rawBytes) + encryptor.finalize()
    return encryptedBytes


def decryptBytes(
    cipher: Cipher, encryptedBytes: bytes, autoUnpad: bool = True
) -> bytes:
    decryptor = cipher.decryptor()
    decryptedBytes = decryptor.update(encryptedBytes) + decryptor.finalize()
    if autoUnpad:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decryptedBytes = unpadder.update(decryptedBytes) + unpadder.finalize()
    return decryptedBytes


def generateInitVector() -> bytes:
    return os.urandom(16)


def generateCipher(
    sessionKey: bytes, iv: bytes = generateInitVector()
) -> tuple[Cipher, bytes]:
    cipher = Cipher(algorithms.AES(sessionKey), modes.CBC(iv))
    return cipher, iv


def generateFinished(sessionKey: bytes, finishedLabel: bytes, messages: bytes):
    hashValue = hashes.Hash(hashes.SHA256())
    hashValue.update(messages)
    hashValue = hashValue.finalize()

    prf = hmac.HMAC(sessionKey, hashes.SHA256())
    prf.update(finishedLabel)
    prf.update(hashValue)
    prf = prf.finalize()

    return prf
```

### 9.3.1.4 client.py

```python
# udp.client
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
```

### 9.3.1.5 error.py

```python
# udp.error
from enum import Enum


class Major(Enum):
    ERROR = 0
    CONNECTION = 1
    DISCONNECT = 2
    PACKET = 3


class Minor(Enum):
    pass


class PaperClipError(Exception):
    """Unknown error"""


# connection
class ConnectionErrorCodes(Minor):
    CONNECTION = 0
    NO_SPACE = 1
    CERTIFICATE_INVALID = 2
    FINISH_INVALID = 3


class ConnectionError(PaperClipError):
    """Handshake connection could not be finished"""


class NoSpaceError(ConnectionError):
    """Server has insufficient space to accept new clients"""


class CertificateInvalidError(ConnectionError):
    """Certificate is invalid / can not be validated"""


class FinishInvalidError(ConnectionError):
    """Finish is invalid"""


_connectionErrors = {
    ConnectionErrorCodes.CONNECTION: ConnectionError,
    ConnectionErrorCodes.NO_SPACE: NoSpaceError,
    ConnectionErrorCodes.CERTIFICATE_INVALID: CertificateInvalidError,
    ConnectionErrorCodes.FINISH_INVALID: FinishInvalidError,
}


def getConnectionError(minor: ConnectionErrorCodes | int) -> ConnectionError:
    try:
        minor = minor if isinstance(minor, Minor) else ConnectionErrorCodes(minor)
        if minor in _connectionErrors:
            return _connectionErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError


def getConnectionCode(error: ConnectionError) -> ConnectionErrorCodes:
    try:
        return list(_connectionErrors.keys())[
            list(_connectionErrors.values()).index(error)
        ]
    except ValueError:
        return PaperClipError


# disconnect
class DisconnectErrorCodes(Minor):
    DISCONNECT = 0
    SERVER_DISCONNECT = 1
    CLIENT_DISCONNECT = 2


class DisconnectError(PaperClipError):
    """A party is disconnecting"""


class ServerDisconnectError(DisconnectError):
    """The server is closing"""


class ClientDisconnectError(DisconnectError):
    """The client is closing"""


_disconnectErrors = {
    DisconnectErrorCodes.DISCONNECT: DisconnectError,
    DisconnectErrorCodes.SERVER_DISCONNECT: ServerDisconnectError,
    DisconnectErrorCodes.CLIENT_DISCONNECT: ClientDisconnectError,
}


def getDisconnectError(minor: DisconnectErrorCodes | int) -> DisconnectError:
    try:
        minor = minor if isinstance(minor, Minor) else DisconnectErrorCodes(minor)
        if minor in _disconnectErrors:
            return _disconnectErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError


def getDisconnectCode(error: DisconnectError) -> DisconnectErrorCodes:
    try:
        return list(_disconnectErrors.keys())[
            list(_disconnectErrors.values()).index(error)
        ]
    except ValueError:
        return PaperClipError


# packet
class PacketErrorCodes(Minor):
    PACKET = 0
    VERSION = 1
    PACKET_TYPE = 2
    FLAGS = 3
    SEQUENCE_ID = 4
    FRAGMENT_ID = 5
    FRAGMENT_NUMBER = 6
    INIT_VECTOR = 7
    COMPRESSION = 8
    CHECKSUM = 9


class PacketError(PaperClipError):
    """Packet cannot be read"""


class VersionError(PacketError):
    """Packet Version is invalid / does not match expected"""


class PacketTypeError(PacketError):
    """Packet Type is invalid / unknown"""


class FlagsError(PacketError):
    """Flags are invalid / unknown"""


class SequenceIdError(PacketError):
    """Sequence Id is invalid / does not match expected"""


class FragmentIdError(PacketError):
    """Fragment Id is invalid / unknown"""


class FragmentNumberError(PacketError):
    """Fragment Number is invalid / unknown"""


class InitVectorError(PacketError):
    """Init Vector is invalid / unknown i.e. decrypt fail"""


class CompressionError(PacketError):
    """Decompression fail"""


class ChecksumError(PacketError):
    """Checksum is invalid / unknown i.e. checksum fail"""


_packetErrors = {
    PacketErrorCodes.PACKET: PacketError,
    PacketErrorCodes.VERSION: VersionError,
    PacketErrorCodes.PACKET_TYPE: PacketTypeError,
    PacketErrorCodes.FLAGS: FlagsError,
    PacketErrorCodes.SEQUENCE_ID: SequenceIdError,
    PacketErrorCodes.FRAGMENT_ID: FragmentIdError,
    PacketErrorCodes.FRAGMENT_NUMBER: FragmentNumberError,
    PacketErrorCodes.INIT_VECTOR: InitVectorError,
    PacketErrorCodes.COMPRESSION: CompressionError,
    PacketErrorCodes.CHECKSUM: ChecksumError,
}


def getPacketError(minor: PacketErrorCodes | int) -> PacketError:
    try:
        minor = minor if isinstance(minor, Minor) else PacketErrorCodes(minor)
        if minor in _packetErrors:
            return _packetErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError


def getPacketCode(error: PacketError) -> PacketErrorCodes:
    try:
        return list(_packetErrors.keys())[list(_packetErrors.values()).index(error)]
    except ValueError:
        return PaperClipError


# convenience
def getError(major: Major | int, minor: Minor | int = 0) -> PaperClipError:
    try:
        major = major if isinstance(major, Major) else Major(major)
        match major:
            case Major.CONNECTION:
                return getConnectionError(minor)
            case Major.DISCONNECT:
                return getDisconnectError(minor)
            case Major.PACKET:
                return getPacketError(minor)
            case _:
                return PaperClipError
    except TypeError:
        return PaperClipError


def getMinor(major: Major, minor: int) -> Minor:
    match major:
        case Major.CONNECTION:
            return ConnectionErrorCodes(minor)
        case Major.DISCONNECT:
            return DisconnectErrorCodes(minor)
        case Major.PACKET:
            return PacketErrorCodes(minor)
        case _:
            return Minor


def getErrorCode(error: PaperClipError) -> tuple[Major, Minor]:
    match error:
        case c if issubclass(c, ConnectionError):
            return (Major.CONNECTION, getConnectionCode(error))
        case d if issubclass(d, DisconnectError):
            return (Major.DISCONNECT, getDisconnectCode(error))
        case p if issubclass(p, PacketError):
            return (Major.PACKET, getPacketCode(error))
        case _:
            return (Major.ERROR, Minor)
```

### 9.3.1.6 node.py

```python
# udp.node
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
                        self.queue.task_done()
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
```

### 9.3.1.7 packet.py

```python
# udp.packet
import struct
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate

from . import auth, error, logger, utils

VERSION = 0
# SIZE in Bits
VERSION_SIZE = 4
PACKET_TYPE_SIZE = 4
FLAGS_SIZE = 8
SEQUENCE_ID_SIZE = 16
FRAGMENT_ID_SIZE = 8
FRAGMENT_NUM_SIZE = 8
INIT_VECTOR_SIZE = 16
CHECKSUM_SIZE = 16
ACK_ID_SIZE = SEQUENCE_ID_SIZE  # 16
ACK_BITS_SIZE = SEQUENCE_ID_SIZE  # 16


class Type(Enum):
    DEFAULT = 0
    ACK = 1
    AUTH = 2
    HEARTBEAT = 3
    ERROR = 4


class Flag(Enum):
    RELIABLE = 0
    CHECKSUM = 1
    COMPRESSED = 2
    ENCRYPTED = 3
    FRAG = 4


class Heartbeat(Enum):
    PING = 0
    PONG = 1


def lazyFlags(*fs: list[Flag]) -> list[int]:
    flags = [0 for _ in range(FLAGS_SIZE)]
    for flag in fs:
        flags[flag.value] = 1
    return flags


class Packet:
    version: int = VERSION
    packet_type: Type = Type.DEFAULT
    flags: list[int] = [0 for _ in range(FLAGS_SIZE)]
    sequence_id: int = 0
    fragment_id: int | None = None
    fragment_number: int | None = None
    init_vector: int | None = None
    checksum: int | None = None
    _data: bytes | None = None

    def __init__(
        self,
        version: int = VERSION,
        packet_type: Type = Type.DEFAULT,
        flags: list[int] = [0 for _ in range(FLAGS_SIZE)],
        sequence_id: int = None,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        data: bytes | None = None,
    ) -> None:
        self.version = version
        self.packet_type = packet_type
        self.flags = flags
        self.sequence_id = sequence_id
        self.fragment_id = fragment_id
        self.fragment_number = fragment_number
        self.init_vector = init_vector
        self.checksum = checksum
        self.data = data

    # util
    def encryptData(self, session_key: bytes) -> None:
        try:
            self.flags[Flag.ENCRYPTED.value] = 1
            iv = (
                self.init_vector
                if self.init_vector is not None
                else auth.generateInitVector()
            )
            cipher, iv = auth.generateCipher(session_key, iv)
            self.init_vector = iv
            self.data = auth.encryptBytes(cipher, self.data)
        except Exception as e:
            raise error.InitVectorError(e)

    def decryptData(self, session_key: bytes) -> None:
        try:
            if self.flags[Flag.ENCRYPTED.value]:
                cipher = auth.generateCipher(session_key, self.init_vector)[0]
                self.data = auth.decryptBytes(cipher, self.data)
            else:
                logger.warning(
                    f"Packet {self} is not flagged as ENCRYPTED ({self.flags})."
                )
        except Exception as e:
            raise error.InitVectorError(e)

    def compressData(self) -> None:
        try:
            self.flags[Flag.COMPRESSED.value] = 1
            self.data = utils.compressData(self.data)
        except Exception as e:
            raise error.CompressionError(e)

    def decompressData(self) -> None:
        try:
            if self.flags[Flag.COMPRESSED.value]:
                self.data = utils.decompressData(self.data)
            else:
                logger.warning(
                    f"Packet {self} is not flagged as COMPRESSED ({self.flags})."
                )
        except Exception as e:
            raise error.CompressionError(e)

    def setChecksum(self) -> None:
        try:
            self.flags[Flag.CHECKSUM.value] = 1
            data = self.data if self.data is not None else b""
            self.checksum = utils.generateChecksum(data)
        except Exception as e:
            raise error.ChecksumError(e)

    def validateChecksum(self) -> bool:
        try:
            if self.flags[Flag.CHECKSUM.value]:
                data = self.data if self.data is not None else b""
                return self.checksum == utils.generateChecksum(data)
            else:
                logger.warning(
                    f"Packet {self} is not flagged as CHECKSUM ({self.flags})."
                )
        except Exception as e:
            raise error.ChecksumError(e)

    @staticmethod
    def _getHeader(p) -> dict:
        header = {
            k: v
            for k, v in vars(p).items()
            if k not in ("data", "fragment_id", "fragment_number")
        }
        return header

    def fragment(self):
        self.flags[Flag.FRAG.value] = 1
        header = Packet._getHeader(self)
        fragData = utils.fragmentData(self.data)
        fragment_number = len(fragData)
        return [
            self._createFragment(
                header, fragment_id=i, fragment_number=fragment_number, data=data
            )
            for i, data in enumerate(fragData)
        ]

    @classmethod
    def _createFragment(
        cls, header: dict, fragment_id: int, fragment_number: int, data: bytes
    ):
        return cls(
            **header,
            fragment_id=fragment_id,
            fragment_number=fragment_number,
            data=data,
        )

    @classmethod
    def defragment(cls, frags):
        if frags[0].flags[Flag.FRAG.value]:
            header = Packet._getHeader(frags[0])
            header["flags"][Flag.FRAG.value] = 0
            data = utils.defragmentData([frag.data for frag in frags])
            return cls(**header, data=data)
        else:
            logger.warning(
                f"Packet {frags[0]} is not flagged as FRAG ({frags[0].flags})."
            )

    # dunder
    def __str__(self) -> str:
        try:
            s = self.pack(self)
        except error.PaperClipError:
            s = b""
        data = self.data if self.data is not None else b""
        pSize = len(s)
        dSize = len(data)
        if len(data) > 12:
            data = f"{data[:11]}...{str(data[-1:])[1:]}"
        return f"<{self.version}:{self.packet_type.name} {self.sequence_id} {''.join(map(str,self.flags))} {data} [{pSize}:{dSize}]>"

    def __eq__(self, other) -> bool:
        if isinstance(other, self.__class__):
            return vars(self) == vars(other)
        else:
            return False

    # encode / decode
    @staticmethod
    def _encodeVersion(version: int) -> int:
        try:
            return version
        except Exception as e:
            raise error.VersionError(e)

    @staticmethod
    def _decodeVersion(version: int) -> int:
        try:
            return version
        except Exception as e:
            raise error.VersionError(e)

    @staticmethod
    def _encodeType(packet_type: Type) -> int:
        try:
            return packet_type.value
        except Exception as e:
            raise error.PacketTypeError(e)

    @staticmethod
    def _decodeType(packet_type: int) -> Type:
        try:
            return Type(packet_type)
        except Exception as e:
            raise error.PacketTypeError(e)

    @staticmethod
    def encodeVersionType(version: int, packet_type: Type) -> bytes:
        return struct.pack(
            "!B",
            (Packet._encodeVersion(version) * 16) | Packet._encodeType(packet_type),
        )

    @staticmethod
    def decodeVersionType(versionType: bytes) -> tuple[int, Type]:
        versionType = struct.unpack("!B", versionType)[0]
        version = Packet._decodeVersion(versionType >> 4)
        packet_type = Packet._decodeType(versionType & 15)
        return version, packet_type

    @staticmethod
    def encodeFlags(flags: list[int]) -> bytes:
        try:
            return struct.pack("!B", int("".join(map(str, flags)), 2))
        except Exception as e:
            raise error.FlagsError(e)

    @staticmethod
    def decodeFlags(flags: bytes) -> list[int]:
        try:
            flags = struct.unpack("!B", flags)[0]
            flags = [(flags >> i) & 1 for i in range(FLAGS_SIZE)]
            flags.reverse()
            return flags
        except Exception as e:
            raise error.FlagsError(e)

    @staticmethod
    def encodeSequenceId(sequence_id: int) -> bytes:
        try:
            return struct.pack("!I", sequence_id)
        except Exception as e:
            raise error.SequenceIdError(e)

    @staticmethod
    def decodeSequenceId(sequence_id: bytes) -> int:
        try:
            return struct.unpack("!I", sequence_id)[0]
        except Exception as e:
            raise error.SequenceIdError(e)

    @staticmethod
    def encodeFragmentId(fragment_id: int) -> bytes:
        try:
            return struct.pack("!B", fragment_id)
        except Exception as e:
            raise error.FragmentIdError(e)

    @staticmethod
    def decodeFragmentId(fragment_id: bytes) -> int:
        try:
            return struct.unpack("!B", fragment_id)[0]
        except Exception as e:
            raise error.FragmentIdError(e)

    @staticmethod
    def encodeFragmentNumber(fragment_number: int) -> bytes:
        try:
            return struct.pack("!B", fragment_number)
        except Exception as e:
            raise error.FragmentNumberError(e)

    @staticmethod
    def decodeFragmentNumber(fragment_number: bytes) -> int:
        try:
            return struct.unpack("!B", fragment_number)[0]
        except Exception as e:
            raise error.FragmentNumberError(e)

    @staticmethod
    def encodeInitVector(init_vector: bytes) -> bytes:
        try:
            return init_vector
        except Exception as e:
            raise error.InitVectorError(e)

    @staticmethod
    def decodeInitVector(init_vector: bytes) -> bytes:
        try:
            return init_vector
        except Exception as e:
            raise error.InitVectorError(e)

    @staticmethod
    def encodeChecksum(checksum: int) -> bytes:
        try:
            return struct.pack("!I", checksum)
        except Exception as e:
            raise error.ChecksumError(e)

    @staticmethod
    def decodeChecksum(checksum: bytes) -> int:
        try:
            return struct.unpack("!I", checksum)[0]
        except Exception as e:
            raise error.ChecksumError(e)

    @staticmethod
    def encodeHeader(
        version: int,
        packet_type: Type,
        flags: list[int],
        sequence_id: int,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
    ) -> bytes:
        versionType = Packet.encodeVersionType(version, packet_type)
        flags = Packet.encodeFlags(flags)
        sequence_id = Packet.encodeSequenceId(sequence_id)
        fragment_id = (
            Packet.encodeFragmentId(fragment_id) if fragment_id is not None else b""
        )
        fragment_number = (
            Packet.encodeFragmentNumber(fragment_number)
            if fragment_number is not None
            else b""
        )
        init_vector = (
            Packet.encodeInitVector(init_vector) if init_vector is not None else b""
        )
        checksum = Packet.encodeChecksum(checksum) if checksum is not None else b""
        return (
            versionType
            + flags
            + sequence_id
            + fragment_id
            + fragment_number
            + init_vector
            + checksum
        )

    @staticmethod
    def decodeHeader(
        header: bytes,
    ) -> tuple[
        int, Type, list[int], int, int | None, int | None, int | None, int | None, int
    ]:
        version, packet_type = Packet.decodeVersionType(header[0:1])
        flags = Packet.decodeFlags(header[1:2])
        sequence_id = Packet.decodeSequenceId(header[2:6])
        offset = 6
        if flags[Flag.FRAG.value]:
            fragment_id = Packet.decodeFragmentId(header[offset : offset + 1])
            fragment_number = Packet.decodeFragmentNumber(
                header[offset + 1 : offset + 2]
            )
            offset += 2
        else:
            fragment_id = None
            fragment_number = None
        if flags[Flag.ENCRYPTED.value]:
            init_vector = Packet.decodeInitVector(header[offset : offset + 16])
            offset += 16
        else:
            init_vector = None
        if flags[Flag.CHECKSUM.value]:
            checksum = Packet.decodeChecksum(header[offset : offset + 4])
            offset += 4
        else:
            checksum = None
        return (
            version,
            packet_type,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
            offset,
        )

    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(
            p.version,
            p.packet_type,
            p.flags,
            p.sequence_id,
            p.fragment_id,
            p.fragment_number,
            p.init_vector,
            p.checksum,
        )
        return header

    @classmethod
    def pack(cls, p) -> bytes:
        header = cls._packHeader(p)
        data = p.data if p.data is not None else b""
        return header + data

    @classmethod
    def _unpackHeader(cls, bytesP: bytes):
        *header, offset = cls.decodeHeader(bytesP)
        return *header, offset

    @classmethod
    def unpack(cls, bytesP: bytes):
        *header, offset = cls._unpackHeader(bytesP)
        data = bytesP[offset:] if offset < len(bytesP) else None
        return cls(*header, data=data)


class AckPacket(Packet):
    ack_id: int = 0
    ack_bits: list[int | None] = [None for _ in range(ACK_BITS_SIZE)]

    def __init__(
        self,
        version: int = VERSION,
        packet_type: Type.ACK = Type.ACK,
        flags: list[int] = [0 for _ in range(FLAGS_SIZE)],
        sequence_id: int = None,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        ack_id: int = None,
        ack_bits: list[int | None] = [None for _ in range(ACK_BITS_SIZE)],
        data: bytes | None = None,
    ) -> None:
        super().__init__(
            version,
            Type.ACK,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
            data,
        )
        self.ack_id = ack_id
        self.ack_bits = ack_bits

    # dunder
    def __str__(self) -> str:
        s = self.pack(self)
        data = self.data if self.data is not None else b""
        pSize = len(s)
        dSize = len(data)
        if len(data) > 12:
            data = f"{data[:11]}...{str(data[-1:])[1:]}"
        return f"<{self.version}:{self.packet_type.name} {self.sequence_id}:{self.ack_id} {''.join(map(str,self.flags))} {data} [{pSize}:{dSize}]>"

    # encode / decode
    @staticmethod
    def encodeAckId(ack_id: int) -> bytes:
        return struct.pack("!I", ack_id)

    @staticmethod
    def decodeAckId(ack_id: bytes) -> int:
        return struct.unpack("!I", ack_id)[0]

    @staticmethod
    def encodeAckBits(ack_bits: list[int]) -> bytes:
        return struct.pack(
            "!I",
            int(
                "".join(
                    map(str, (int(bit) if bit is not None else 0 for bit in ack_bits))
                ),
                2,
            ),
        )

    @staticmethod
    def decodeAckBits(ack_bits: bytes) -> list[int]:
        ack_bits = struct.unpack("!I", ack_bits)[0]
        ack_bits = [(ack_bits >> i) & 1 for i in range(ACK_BITS_SIZE)]
        ack_bits.reverse()
        return ack_bits

    @staticmethod
    def encodeHeader(
        version: int,
        packet_type: Type,
        flags: list[int],
        sequence_id: int,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        ack_id: int = 0,
        ack_bits: list[int | None] = [None for _ in range(ACK_BITS_SIZE)],
    ) -> bytes:
        header = Packet.encodeHeader(
            version,
            packet_type,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
        )
        ack_id = AckPacket.encodeAckId(ack_id)
        ack_bits = AckPacket.encodeAckBits(ack_bits)
        return header + ack_id + ack_bits

    @staticmethod
    def decodeHeader(
        header: bytes,
    ) -> tuple[
        int,
        Type,
        list[int],
        int,
        int | None,
        int | None,
        int | None,
        int | None,
        int,
        list[int | None],
        int,
    ]:
        *h, offset = Packet.decodeHeader(header)
        ack_id = AckPacket.decodeAckId(header[offset : offset + 4])
        offset += 4
        ack_bits = AckPacket.decodeAckBits(header[offset : offset + 4])
        offset += 4
        return *h, ack_id, ack_bits, offset

    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(
            p.version,
            p.packet_type,
            p.flags,
            p.sequence_id,
            p.fragment_id,
            p.fragment_number,
            p.init_vector,
            p.checksum,
            p.ack_id,
            p.ack_bits,
        )
        return header


class AuthPacket(Packet):
    _public_key_size: int | None = None
    public_key: EllipticCurvePublicKey | None = None
    _certificate_size: int | None = None
    certificate: Certificate | None = None

    def __init__(
        self,
        version: int = VERSION,
        packet_type: Type = Type.AUTH,
        flags: list[int] = [0 for _ in range(FLAGS_SIZE)],
        sequence_id: int = None,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        public_key_size: int | None = None,
        public_key: EllipticCurvePublicKey = None,
        certificate_size: int | None = None,
        certificate: Certificate | None = None,
    ) -> None:
        super().__init__(
            version,
            Type.AUTH,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
            data=None,
        )
        self.public_key_size = public_key_size
        self.public_key = public_key
        self.certificate_size = certificate_size
        self.certificate = certificate

    # setter / getter
    @property
    def public_key_size(self) -> int | None:
        if self._public_key_size is None:
            self.public_key_size = (
                AuthPacket.getPublicKeyBytesSize(self.public_key)
                if self.public_key is not None
                else None
            )
        return self._public_key_size

    @public_key_size.setter
    def public_key_size(self, v: int | None) -> None:
        self._public_key_size = v

    @staticmethod
    def getPublicKeyBytesSize(publicKey: EllipticCurvePublicKey) -> int:
        return len(auth.getDerFromPublicEc(publicKey))

    @property
    def certificate_size(self) -> int | None:
        if self._certificate_size is None:
            self.certificate_size = (
                self.getCertificateByteSize(self.certificate)
                if self.certificate is not None
                else None
            )
        return self._certificate_size

    @certificate_size.setter
    def certificate_size(self, v: int | None) -> None:
        self._certificate_size = v

    @staticmethod
    def getCertificateByteSize(certificate: Certificate) -> int:
        return len(auth.getDerFromCertificate(certificate))

    # encode / decode
    @staticmethod
    def encodePublicKeySize(public_key_size: int) -> bytes:
        return struct.pack("!B", public_key_size)

    @staticmethod
    def decodePublicKeySize(public_key_size: bytes) -> int:
        return struct.unpack("!B", public_key_size)[0]

    @staticmethod
    def encodePublicKey(public_key: EllipticCurvePublicKey) -> bytes:
        return auth.getDerFromPublicEc(public_key)

    @staticmethod
    def decodePublicKey(public_key: bytes) -> EllipticCurvePublicKey:
        return auth.getPublicEcFromDer(public_key)

    @staticmethod
    def encodeCertificateSize(certificate_size: int) -> bytes:
        return struct.pack("!H", certificate_size)

    @staticmethod
    def decodeCertificateSize(certificate_size: bytes) -> int:
        return struct.unpack("!H", certificate_size)[0]

    @staticmethod
    def encodeCertificate(certificate: Certificate) -> bytes:
        return auth.getDerFromCertificate(certificate)

    @staticmethod
    def decodeCertificate(certificate: bytes) -> Certificate:
        return auth.getCertificateFromDer(certificate)

    @staticmethod
    def encodeHeader(
        version: int,
        packet_type: Type,
        flags: list[int],
        sequence_id: int,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        public_key_size: int | None = None,
        public_key: EllipticCurvePublicKey | None = None,
        certificate_size: int | None = None,
        certificate: Certificate | None = None,
    ) -> bytes:
        header = Packet.encodeHeader(
            version,
            packet_type,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
        )
        public_key_size = AuthPacket.encodePublicKeySize(public_key_size)
        public_key = AuthPacket.encodePublicKey(public_key)
        certificate_size = (
            AuthPacket.encodeCertificateSize(certificate_size)
            if certificate_size is not None
            else b""
        )
        certificate = (
            AuthPacket.encodeCertificate(certificate)
            if certificate is not None
            else b""
        )
        return header + public_key_size + public_key + certificate_size + certificate

    @staticmethod
    def decodeHeader(
        header: bytes,
    ) -> tuple[
        int,
        Type,
        list[int],
        int,
        int | None,
        int | None,
        int | None,
        int | None,
        int,
        EllipticCurvePublicKey,
        int | None,
        Certificate | None,
        int,
    ]:
        *h, offset = Packet.decodeHeader(header)
        public_key_size = AuthPacket.decodePublicKeySize(header[offset : offset + 1])
        offset += 1
        public_key = AuthPacket.decodePublicKey(
            header[offset : offset + public_key_size]
        )
        offset += public_key_size
        if offset < len(header):  # check if more bytes left to decode
            certificate_size = AuthPacket.decodeCertificateSize(
                header[offset : offset + 2]
            )
            offset += 2
            certificate = AuthPacket.decodeCertificate(
                header[offset : offset + certificate_size]
            )
            offset += certificate_size
        else:
            certificate_size = None
            certificate = None
        return *h, public_key_size, public_key, certificate_size, certificate, offset

    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(
            p.version,
            p.packet_type,
            p.flags,
            p.sequence_id,
            p.fragment_id,
            p.fragment_number,
            p.init_vector,
            p.checksum,
            p.public_key_size,
            p.public_key,
            p.certificate_size,
            p.certificate,
        )
        return header

    @classmethod
    def unpack(cls, bytesP: bytes):
        *header, offset = cls._unpackHeader(bytesP)
        return cls(*header)


class HeartbeatPacket(Packet):
    heartbeat: bool

    def __init__(
        self,
        version: int = VERSION,
        packet_type: Type = Type.HEARTBEAT,
        flags: list[int] = [0 for _ in range(FLAGS_SIZE)],
        sequence_id: int = None,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        heartbeat: bool = 0,
        data: bytes | None = None,
    ) -> None:
        super().__init__(
            version,
            Type.HEARTBEAT,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
            data,
        )
        self.heartbeat = heartbeat

    # encode / decode
    @staticmethod
    def encodeHeartbeat(heartbeat: bool) -> bytes:
        return struct.pack("!?", heartbeat)

    @staticmethod
    def decodeHeartbeat(heartbeat: bytes) -> bool:
        return struct.unpack("!?", heartbeat)[0]

    @staticmethod
    def encodeHeader(
        version: int,
        packet_type: Type,
        flags: list[int],
        sequence_id: int,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        heartbeat: bool = 0,
    ) -> bytes:
        header = Packet.encodeHeader(
            version,
            packet_type,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
        )
        heartbeat = HeartbeatPacket.encodeHeartbeat(heartbeat)
        return header + heartbeat

    @staticmethod
    def decodeHeader(
        header: bytes,
    ) -> tuple[
        int,
        Type,
        list[int],
        int,
        int | None,
        int | None,
        int | None,
        int | None,
        bool,
        int,
    ]:
        *h, offset = Packet.decodeHeader(header)
        heartbeat = HeartbeatPacket.decodeHeartbeat(header[offset : offset + 1])
        offset += 1
        return *h, heartbeat, offset

    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(
            p.version,
            p.packet_type,
            p.flags,
            p.sequence_id,
            p.fragment_id,
            p.fragment_number,
            p.init_vector,
            p.checksum,
            p.heartbeat,
        )
        return header


class ErrorPacket(Packet):
    _major: error.Major
    _minor: error.Minor

    def __init__(
        self,
        version: int = VERSION,
        packet_type: Type = Type.ERROR,
        flags: list[int] = [0 for _ in range(FLAGS_SIZE)],
        sequence_id: int = None,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        major: error.Major | int = error.Major.ERROR,
        minor: error.Minor | int = 0,
        data: bytes | None = None,
    ) -> None:
        super().__init__(
            version,
            Type.ERROR,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
            data,
        )
        self.major = major
        self.minor = minor

    @property
    def major(self) -> error.Major:
        return self._major

    @major.setter
    def major(self, v: error.Major | int):
        if isinstance(v, error.Major):
            self._major = v
        else:
            self._major = error.Major(v)

    @property
    def minor(self) -> error.Minor:
        return self._minor

    @minor.setter
    def minor(self, v: error.Minor | int):
        if isinstance(v, error.Minor):
            self._minor = v
        else:
            self._minor = error.getMinor(self.major, v)

    # dunder
    def __str__(self) -> str:
        s = self.pack(self)
        data = self.data if self.data is not None else b""
        pSize = len(s)
        dSize = len(data)
        return f"<{self.version}:{self.packet_type.name} {self.sequence_id} {''.join(map(str,self.flags))} {self.major.name}.{self.minor.name}: {data} [{pSize}:{dSize}]>"

    # encode / decode
    @staticmethod
    def _encodeMajor(major: error.Major) -> int:
        return major.value

    @staticmethod
    def _decodeMajor(major: int) -> error.Major:
        return error.Major(major)

    @staticmethod
    def _encodeMinor(minor: error.Minor) -> int:
        return minor.value if minor != error.Minor else 0

    @staticmethod
    def _decodeMinor(major: error.Major, minor: int) -> error.Minor:
        return error.getMinor(major, minor)

    def encodeMajorMinor(major: int, minor: int) -> bytes:
        majorMinor = (ErrorPacket._encodeMajor(major) * 16) | ErrorPacket._encodeMinor(
            minor
        )
        return struct.pack("!B", majorMinor)

    def decodeMajorMinor(majorMinor: bytes) -> tuple[int, int]:
        majorMinor = struct.unpack("!B", majorMinor)[0]
        major = ErrorPacket._decodeMajor(majorMinor >> 4)
        minor = ErrorPacket._decodeMinor(major, majorMinor & 15)
        return major, minor

    @staticmethod
    def encodeHeader(
        version: int,
        packet_type: Type,
        flags: list[int],
        sequence_id: int,
        fragment_id: int | None = None,
        fragment_number: int | None = None,
        init_vector: int | None = None,
        checksum: int | None = None,
        major: int = 0,
        minor: int = 0,
    ) -> bytes:
        header = Packet.encodeHeader(
            version,
            packet_type,
            flags,
            sequence_id,
            fragment_id,
            fragment_number,
            init_vector,
            checksum,
        )
        majorMinor = ErrorPacket.encodeMajorMinor(major, minor)
        return header + majorMinor

    @staticmethod
    def decodeHeader(
        header: bytes,
    ) -> tuple[
        int,
        Type,
        list[int],
        int,
        int | None,
        int | None,
        int | None,
        int | None,
        int,
        int,
        int,
    ]:
        *h, offset = Packet.decodeHeader(header)
        major, minor = ErrorPacket.decodeMajorMinor(header[offset : offset + 1])
        offset += 1
        return *h, major, minor, offset

    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(
            p.version,
            p.packet_type,
            p.flags,
            p.sequence_id,
            p.fragment_id,
            p.fragment_number,
            p.init_vector,
            p.checksum,
            p.major,
            p.minor,
        )
        return header


def unpack(rawP:bytes) -> Packet:
    packet_type = Packet.decodeVersionType(rawP[0:1])[1]
    match packet_type:
        case Type.DEFAULT:
            return Packet.unpack(rawP)
        case Type.ACK:
            return AckPacket.unpack(rawP)
        case Type.AUTH:
            return AuthPacket.unpack(rawP)
        case Type.HEARTBEAT:
            return HeartbeatPacket.unpack(rawP)
        case Type.ERROR:
            return ErrorPacket.unpack(rawP)
        case _:
            logger.warning(f"Cannot unpack '{packet_type}' due to invalid packet type.")
```

### 9.3.1.8 server.py

```python
# udp.server
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
```

### 9.3.1.9 utils.py

```python
# udp.utils
import zlib

from . import MAX_FRAGMENT_SIZE


def compressData(data: bytes) -> bytes:
    # default speed
    # no header or checksum
    return zlib.compress(data, -1, -15)


def decompressData(data: bytes) -> bytes:
    # no header or checksum
    return zlib.decompress(data, -15)


def generateChecksum(data: bytes) -> int:
    return zlib.crc32(data)


def fragmentData(data: bytes) -> list[bytes]:
    return [
        data[i : i + MAX_FRAGMENT_SIZE] for i in range(0, len(data), MAX_FRAGMENT_SIZE)
    ]


def defragmentData(fragments: list[bytes]) -> bytes:
    return b"".join(fragments)
```

## 9.3.2 server

### 9.3.2.1 __init__.py

```python
# server.__init__
import os

import dotenv
from flask import Flask

from udp import logger  # noqa: F401

from .models import *  # noqa: F403

from sqlalchemy_utils import database_exists, create_database

dotenv.load_dotenv()
PRUNE_TIME = int(os.environ.get("PRUNE_TIME"))


def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY").encode()
    uri = os.environ.get("SQLALCHEMY_DATABASE_URI")
    _init = False
    if not database_exists(uri):
        _init = True
        create_database(uri)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri

    db.init_app(app)  # noqa: F405

    with app.app_context():
        db.create_all()  # noqa: F405
        
    if _init:
        with app.app_context():
            # init games
            from rps import ID, NAME, MIN_PLAYERS, MAX_PLAYERS
            Statement.createGame(ID, NAME, MIN_PLAYERS, MAX_PLAYERS)  # noqa: F405
            # example accounts
            m = Statement.createAccount("Mario", "ItsAMe123")  # noqa: F405
            p = Statement.createAccount("Peach", "MammaMia!")  # noqa: F405
            b = Statement.createAccount("Bowser", "M4r10SucK5")  # noqa: F405
            Statement.createFriends(m.id, p.id)  # noqa: F405
            Statement.createFriends(p.id, b.id)  # noqa: F405

    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    return app
```

### 9.3.2.2 lobbies.py

```python
# server.lobbies
import os

import dotenv
from flask import Flask

from udp import logger  # noqa: F401

from .models import *  # noqa: F403

from sqlalchemy_utils import database_exists, create_database

dotenv.load_dotenv()
PRUNE_TIME = int(os.environ.get("PRUNE_TIME"))


def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY").encode()
    uri = os.environ.get("SQLALCHEMY_DATABASE_URI")
    _init = False
    if not database_exists(uri):
        _init = True
        create_database(uri)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri

    db.init_app(app)  # noqa: F405

    with app.app_context():
        db.create_all()  # noqa: F405
        
    if _init:
        with app.app_context():
            # init games
            from rps import ID, NAME, MIN_PLAYERS, MAX_PLAYERS
            Statement.createGame(ID, NAME, MIN_PLAYERS, MAX_PLAYERS)  # noqa: F405
            # example accounts
            m = Statement.createAccount("Mario", "ItsAMe123")  # noqa: F405
            p = Statement.createAccount("Peach", "MammaMia!")  # noqa: F405
            b = Statement.createAccount("Bowser", "M4r10SucK5")  # noqa: F405
            Statement.createFriends(m.id, p.id)  # noqa: F405
            Statement.createFriends(p.id, b.id)  # noqa: F405

    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    return app
```

### 9.3.2.3 main.py

```python
# server.main
import atexit
import base64

from flask import (
    Blueprint,
    abort,
    g,
    jsonify,
    request,
)
from flask_httpauth import HTTPBasicAuth

import udp.auth

from . import Statement
from .lobbies import LobbyHandler

main = Blueprint("main", __name__)
auth = HTTPBasicAuth()
rsaKey = udp.auth.generateRsaKey()
lobbyHandler = LobbyHandler(rsaKey=rsaKey)


def quit() -> None:
    lobbyHandler.quit()


atexit.register(quit)


@auth.verify_password
def verifyPassword(username: str, password: str) -> bool:
    account = Statement.validateToken(username)  # check token
    if not account:  # if token not valid
        account = Statement.findAccount(username=username)  # check account
        if not account or not account.verifyPassword(
            password
        ):  # if account not exist or wrong password
            return False
    g.account = account
    return True


# Index
@main.route("/")
def index():
    return jsonify({})


# auth
@main.route("/auth/register", methods=["POST"])
def createAccount():
    username = request.json.get("username")
    password = request.json.get("password")
    if not (username or password):  # check not null
        abort(400)  # missing args
    if Statement.findAccount(username):  # check if account exists
        abort(400)  # account already exists
    account = Statement.createAccount(username, password)
    return jsonify({"account-id": account.id, "username": account.username}), 201


@main.route("/auth/token")
@auth.login_required
def getAuthToken():
    return jsonify({"token": g.account.generateToken()})


@main.route("/auth/key")
@auth.login_required
def getKey():
    return jsonify(
        {
            "key": base64.encodebytes(g.account.private_key).decode(),
            "account-id": g.account.id,
        }
    )


@main.route("/auth/certificate")
@auth.login_required
def getCert():
    # return server certificate
    return None


@main.route("/auth/certificate/validate")
def validateCert():
    valid = False
    certificate = request.json.get("certificate")
    certificate = base64.decodebytes(certificate.encode())
    if certificate is not None:
        certificate = udp.auth.getCertificateFromDer(certificate)
        attributes = udp.auth.getUserCertificateAttributes(certificate)
        if attributes["account-id"] is not None:
            account = Statement.getAccount(attributes["account-id"])
            publicKey = udp.auth.getRsaPublicFromDer(account.public_key)
        else:
            publicKey = rsaKey.public_key()
        valid = udp.auth.validateCertificate(certificate, publicKey)
        return jsonify({"valid": valid, "account-id": attributes["account-id"]})
    else:
        abort(400)  # missing args


@main.route("/auth/test")
@auth.login_required
def authTest():
    return jsonify({"hello": g.account.username})


# game
@main.route("/games/")
@auth.login_required
def getGames():
    return jsonify({game.id: game.name for game in Statement.getGames()})


@main.route("/lobby/all")
@auth.login_required
def getLobbies():
    lobbies = LobbyHandler.getAll()
    games = {game.id: game.name for game in Statement.getGames()}
    data = lambda lobby: {  # noqa: E731
        "game": {"game-id": lobby.game_id, "game-name": games[lobby.game_id]},
        "size": Statement.getLobbySize(lobby.id),
        "is-full": Statement.getIsLobbyFree(lobby.id),
    }
    return jsonify({lobby.id: data(lobby) for lobby in lobbies})


@main.route("/lobby/create", methods=["POST"])
@auth.login_required
def createLobby():
    gameId = request.json.get("game-id")
    gameName = request.json.get("game-name")
    if not (gameId or gameName):  # check args
        abort(400)  # missing args
    game = None
    if gameId:  # check gameId not null
        game = Statement.getGame(gameId)
    if not game:  # check gameId null
        if gameName:  # check gameName not null
            game = Statement.findGame(gameName)
    if not game:  # check game null
        abort(404)  # no game found
    addr = _getAddr()
    lobby = lobbyHandler.createLobby(addr, game.id)
    return jsonify(
        {"lobby-id": lobby.id, "lobby-addr": lobby.getAddr(), "game-id": lobby.gameId}
    ), 201


def _getAddr():
    host, port = request.host.split(":")
    port = int(port)
    return (host, port)


@main.route("/lobby/")
@auth.login_required
def getLobby():
    lobbyId = request.json.get("lobby-id")
    if not lobbyId:
        abort(400)  # missing args
    lobby = lobbyHandler.getLobby(lobbyId)
    return jsonify(
        {"lobby-id": lobby.id, "lobby-addr": lobby.getAddr(), "game-id": lobby.gameId}
    )


@main.route("/lobby/members")
@auth.login_required
def getMembers():
    return jsonify(lobbyHandler.getMembers)


@main.route("/lobby/find")
@auth.login_required
def findLobby():
    gameId = request.json.get("game-id")
    gameName = request.json.get("game-name")
    if not (gameId or gameName):  # check args
        abort(400)  # missing args
    game = None
    if gameId:  # check gameId not null
        game = Statement.getGame(gameId)
    if not game:  # check gameId null
        if gameName:  # check gameName not null
            game = Statement.findGame(gameName)
    if not game:  # check game null
        abort(404)  # no game found
    lobby = lobbyHandler.findLobbies(game.id)
    lobby = lobby[0] if len(lobby) > 0 else None
    if lobby is not None:
        return jsonify(
            {
                "lobby-id": lobby.id,
                "lobby-addr": lobby.getAddr(),
                "game-id": lobby.gameId,
            }
        )
    else:
        abort(404)


@main.route("/friends/")
@auth.login_required
def getFriends():
    friends = Statement.getFriends(g.account.id)
    return jsonify(
        {
            "friends": [
                {"id": account.id, "username": account.username} for account in friends
            ]
        }
    )


@main.route("/friends/add", methods=["POST"])
@auth.login_required
def addFriend():
    username = request.json.get("username")
    if username is None:
        abort(400)  # missing args
    account = g.account
    other = Statement.findAccount(username)
    if other is None:
        abort(404)
    Statement.createFriends(account.id, other.id)
    return jsonify(
        {
            "account": {"id": account.id, "username": account.username},
            "other": {"id": other.id, "username": other.username},
        }
    ), 201


@main.route("/friend/remove", methods=["DELETE"])
@auth.login_required
def removeFriend():
    username = request.json.get("username")
    if username is None:
        abort(400)  # missing args
    account = g.account
    other = Statement.findAccount(username)
    if other is None:
        abort(404)
    success = Statement.removeFriends(account.id, other.id)
    if success:
        return jsonify(data=[]), 204
    else:
        abort(404)


@main.route("/lobby/friends")
@auth.login_required
def getFriendLobbies():
    friends = Statement.getFriends(g.account.id)
    lobbyInfo = lambda lobby: {  # noqa: E731
        "lobby-id": lobby.id,
        "game-id": lobby.gameId,
        "game-name": Statement.getGame(lobby.gameId).name,
    }
    accountInfo = lambda account: {  # noqa: E731
        "account-id": account.id,
        "username": account.username,
    }
    lobbies = [
        {
            "account": accountInfo(account),
            "lobbies": [
                lobbyInfo(lobby) for lobby in lobbyHandler.getMember(account.id)
            ],
        }
        for account in friends
        if len(lobbyHandler.getMember(account.id)) > 0
    ]
    return jsonify(lobbies)
```

### 9.3.2.4 models.py

```python
# server.models
import datetime

import jwt
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

import udp.auth as auth

db = SQLAlchemy()


# models
class Friends(db.Model):
    account_one_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )
    account_two_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )


class Scores(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable=False)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(162), nullable=False)
    private_key = db.Column(db.LargeBinary(1337))
    public_key = db.Column(db.LargeBinary(294))

    def hashPassword(self, password: str) -> None:
        self.password = generate_password_hash(password)

    def verifyPassword(self, password: str) -> bool:
        return check_password_hash(self.password, password)

    def generateToken(self, expiration: int = 600) -> str:
        data = {
            "id": self.id,
            "exp": datetime.datetime.now() + datetime.timedelta(seconds=expiration),
        }
        token = jwt.encode(data, current_app.config["SECRET_KEY"], algorithm="HS256")
        return token

    @staticmethod
    def validateToken(token: str):
        try:
            data = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                leeway=datetime.timedelta(seconds=10),
                algorithms=["HS256"],
            )
        except:  # noqa: E722
            return None
        account = Statement.getAccount(data.get("id"))
        return account

    def generateKey(self, password: bytes) -> None:
        k = auth.generateRsaKey()
        self.private_key = auth.getDerFromRsaPrivate(k, password)
        self.public_key = auth.getDerFromRsaPublic(k.public_key())

    @staticmethod
    def decryptKey(self, key: bytes, password: bytes) -> auth.rsa.RSAPublicKey:
        k = auth.getRsaPrivateFromDer(key, password)
        return k


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    min_players = db.Column(db.Integer, default=1)
    max_players = db.Column(db.Integer)


class Statement:
    # get
    @staticmethod
    def getGame(gameId: int) -> Game:
        return Game.query.filter_by(id=gameId).scalar()

    @staticmethod
    def getGames() -> list[Game]:
        return Game.query.all()

    @staticmethod
    def getAccount(userId: int) -> Account:
        return Account.query.filter_by(id=userId).scalar()

    @staticmethod
    def getFriends(accountId: int) -> list[Account]:
        friends = Friends.query.filter(
            (Friends.account_one_id == accountId)
            | (Friends.account_two_id == accountId)
        )
        friends = [
            friend.account_one_id
            if friend.account_one_id != accountId
            else friend.account_two_id
            for friend in friends
        ]
        friends = [Statement.getAccount(id) for id in friends]
        return friends

    # create
    @staticmethod
    def createAccount(username: str, password: str) -> Account:
        account = Account(username=username)
        account.hashPassword(password)
        account.generateKey(password.encode())
        db.session.add(account)
        db.session.commit()
        return account

    @staticmethod
    def createFriends(accountIdOne: int, accountIdTwo: int) -> Friends:
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends(account_one_id=idOne, account_two_id=idTwo)
        db.session.add(friends)
        db.session.commit()
        return friends
    
    @staticmethod
    def createGame(id:int, name:str, min_players:int, max_players:int) -> Game:
        game = Game(id=id, name=name, min_players=min_players, max_players=max_players)
        db.session.add(game)
        db.session.commit()
        return game

    # find
    @staticmethod
    def findAccount(username: str) -> Account | None:
        return Account.query.filter_by(username=username).scalar()

    @staticmethod
    def validateToken(token: str) -> Account | None:
        return Account.validateToken(token)

    @staticmethod
    def findGame(gameName: str) -> Game | None:
        return Game.query.filter_by(name=gameName).scalar()

    # delete
    @staticmethod
    def removeFriends(accountIdOne: int, accountIdTwo: int) -> bool:
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends.query.filter(
            (Friends.account_one_id == idOne) & (Friends.account_two_id == idTwo)
        )
        if friends is not None:
            friends.delete()
            db.session.commit()
            return True
        else:
            return False
```

## 9.3.3 rps

### 9.3.3.1 __init__.py

```python
# rps.__init__
import os

import yaml


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class Choice:
    ROCK = 0
    PAPER = 1
    SCISSORS = 2


class Outcome:
    LOOSE = 0
    WIN = 1
    DRAW = 2


QUEUE_TIMEOUT = 10

# config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "game_config.yaml")

with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

ID = config["ID"]
NAME = config["NAME"]
MIN_PLAYERS = config["MIN_PLAYERS"]
MAX_PLAYERS = config["MAX_PLAYERS"]
```

### 9.3.3.2 __main__.py

```python
# rps.__main__
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
```

### 9.3.3.3 client.py

```python
# rps.client
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
                            addr, data = self.recvQueue.get(timeout=QUEUE_TIMEOUT)
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
```

### 9.3.3.4 game_config.yaml

```yaml
# game_config.yaml
NAME: "RPS"
ID: 1
MIN_PLAYERS: 2
MAX_PLAYERS: 2
```

### 9.3.3.5 server.py

```python
# rps.server
import json
from queue import Empty, Queue
from threading import Lock

from udp.auth import rsa
from udp.packet import Flag, lazyFlags
from udp.server import Server as UdpServer

from . import MAX_PLAYERS, QUEUE_TIMEOUT, Choice, Outcome


class Server:
    isRunning: bool
    recvBuffer: Queue
    players: dict[tuple[str, int], dict[str, int]]
    playersLock: Lock
    udpServer: UdpServer
    onClientJoin: None
    onClientLeave: None
    onReceiveData: None

    def __init__(
        self,
        addr: tuple[str, int],
        rsaKey: rsa.RSAPrivateKey | None = None,
        onClientJoin=None,
        onClientLeave=None,
        onReceiveData=None,
    ):
        self.isRunning = True
        self.recvQueue = Queue()
        self.players = {}
        self.playersLock = Lock()
        self.onClientJoin = onClientJoin
        self.onClientLeave = onClientLeave
        self.onReceiveData = onReceiveData
        self.udpServer = UdpServer(
            addr,
            maxClients=MAX_PLAYERS,
            rsaKey=rsaKey,
            onClientJoin=self.playerJoin,
            onClientLeave=self.playerLeave,
            onReceiveData=self.receive,
        )

    def send(self, addr: tuple[str, int], data: dict) -> None:
        self.udpServer.queueDefault(
            addr, flags=lazyFlags(Flag.RELIABLE), data=self.encodeData(data)
        )

    def receive(self, addr: tuple[str, int], data: bytes) -> None:
        self.recvQueue.put((addr, self.decodeData(data)))
        if self.onReceiveData:
            self.onReceiveData(addr, data)

    @staticmethod
    def encodeData(data: dict) -> bytes:
        return json.dumps(data).encode()

    @staticmethod
    def decodeData(data: bytes) -> dict:
        return json.loads(data.decode())

    @staticmethod
    def evaluateWin(choiceOne: int, choiceTwo: int) -> int:
        match choiceOne:
            case Choice.ROCK:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.DRAW
                    case Choice.PAPER:
                        return Outcome.LOOSE
                    case Choice.SCISSORS:
                        return Outcome.WIN
                    case _:
                        raise ValueError
            case Choice.PAPER:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.WIN
                    case Choice.PAPER:
                        return Outcome.DRAW
                    case Choice.SCISSORS:
                        return Outcome.LOOSE
                    case _:
                        raise ValueError
            case Choice.SCISSORS:
                match choiceTwo:
                    case Choice.ROCK:
                        return Outcome.LOOSE
                    case Choice.PAPER:
                        return Outcome.WIN
                    case Choice.SCISSORS:
                        return Outcome.DRAW
                    case _:
                        raise ValueError
            case _:
                raise ValueError

    @staticmethod
    def evaluatePlayerChoices(choices: list[tuple[tuple[str, int], int]]):
        outcomes = [
            (choices[0][0], Server.evaluateWin(choices[0][1], choices[1][1])),
            (choices[1][0], Server.evaluateWin(choices[1][1], choices[0][1])),
        ]
        return outcomes

    def getChoices(self) -> list[tuple[tuple[str, int], int]]:
        choices = {}
        while self.isRunning:
            try:
                addr, data = self.recvQueue.get(timeout=QUEUE_TIMEOUT)
                choices[addr] = data["choice"]
                if len(choices) == 2:
                    choices = [(addr, choice) for addr, choice in choices.items()]
                    self.recvQueue.task_done()
                    return choices
            except Empty:
                pass  # check still running

    def playerJoin(self, addr: tuple[str, int], accountId: int) -> None:
        with self.playersLock:
            self.players[addr] = {"score": 0, "accountId": accountId}
        if self.onClientJoin:
            self.onClientJoin(addr, accountId)

    def playerLeave(self, addr: tuple[str, int], accountId: int) -> None:
        with self.playersLock:
            # TODO: submit score
            del self.players[addr]
        if self.onClientLeave:
            self.onClientLeave(addr, accountId)

    def isNotFull(self) -> bool:
        return self.udpServer.isNotFull()

    def isEmpty(self) -> bool:
        return self.udpServer.isEmpty()

    def getPlayers(self) -> dict[tuple[str, int], dict[str, int]]:
        with self.playersLock:
            return self.players.copy()

    def getPlayer(self, addr: tuple[str, int]) -> int:
        with self.playersLock:
            if addr in self.players:
                return self.players[addr]
            else:
                return None

    def setPlayer(self, addr: tuple[str, int], v: int) -> None:
        with self.playersLock:
            if addr in self.players:
                self.players[addr] = v

    def incrementPlayer(self, addr: tuple[str, int]) -> None:
        with self.playersLock:
            self.players[addr]["score"] += 1

    def getAccountId(self, addr: tuple[str, int]) -> int:
        with self.playersLock:
            return self.players[addr]["accountId"]

    def getAccountIds(self, addr: tuple[str, int]) -> list[int]:
        with self.playersLock:
            return [player["accountId"] for player in self.players.values()]

    @property
    def playerCount(self) -> int:
        with self.playersLock:
            return len(self.players)

    def mainloop(self) -> None:
        self.udpServer.startThreads()
        try:
            while self.isRunning:
                if self.playerCount == MAX_PLAYERS:
                    choices = self.getChoices()
                    outcomes = self.evaluatePlayerChoices(choices)
                    replies = {}
                    for addr, outcome in outcomes:
                        replies[addr] = {
                            "outcome": outcome,
                            "choice": [v for k, v in choices if k == addr][0],
                            "otherChoice": [v for k, v in choices if k != addr][0],
                        }
                        if outcome == Outcome.WIN:
                            self.incrementPlayer(addr)
                    scores = self.getPlayers()
                    for addr in replies:
                        replies[addr] |= {
                            "score": scores[addr],
                            "otherScore": [v for k, v in scores.items() if k != addr][
                                0
                            ],
                        }
                        self.send(addr, replies[addr])
        finally:
            self.quit()

    def quit(self) -> None:
        self.isRunning = False
        self.udpServer.quit()
```

## 9.3.4 client

### 9.3.4.1 __init__.py

```python
# client.__init__
import os
import sys

import dotenv

from udp import logger, logging

dotenv.load_dotenv()

TCP_HOST = os.environ.get("S_HOST")
TCP_PORT = int(os.environ.get("TCP_PORT"))
C_PORT = int(os.environ.get("C_PORT"))
SERVER_URL = f"http://{TCP_HOST}:{TCP_PORT}"

offset = sys.argv[1:]
try:
    offset = int(offset[0])
except ValueError:
    offset = None
except IndexError:
    offset = None

if os.environ.get("DEBUG") is not None:
    logger.setLevel(logging.WARNING)
    while offset is None:
        try:
            offset = int(input("\noffset: "))
        except ValueError:
            print("Invalid input.")
else:
    logger.setLevel(logging.ERROR)

if offset is not None:
    C_PORT += offset
```

### 9.3.4.2 __main__.py

```python
# client.__main__
import base64
import json
import time

import requests
from requests.auth import HTTPBasicAuth

import udp.auth
from rps.client import Client as RpsClient
from udp import bcolors

from . import C_PORT, SERVER_URL, TCP_HOST


class Client:
    id: int
    username: str
    password: str
    gameClient: None
    token: str
    key: udp.auth.rsa.RSAPublicKey
    auth: HTTPBasicAuth

    def __init__(self, username: str, password: str, token: str | None = None) -> None:
        self.username = username
        self.password = password
        self.gameClient = None
        self.token = (
            token if token is not None else self.getToken(self.username, self.password)
        )
        self.auth = HTTPBasicAuth(self.token, "")
        self.getKey(password.encode())

    # auth
    @staticmethod
    def getToken(username: str, password: str) -> str:
        url = SERVER_URL + "/auth/token"
        r = requests.get(url, auth=(username, password))
        assert r.status_code == 200, r
        return r.json()["token"]

    @staticmethod
    def createAccount(username: str, password: str) -> str:
        url = SERVER_URL + "/auth/register"
        headers = {"Content-Type": "application/json"}
        data = {"username": username, "password": password}
        r = requests.post(url, headers=headers, data=json.dumps(data))
        assert r.status_code == 201, r
        return r.json()["username"]

    def getKey(self, password: bytes) -> udp.auth.rsa.RSAPrivateKey:
        url = SERVER_URL + "/auth/key"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        self.id = r.json()["account-id"]
        key = base64.decodebytes(r.json()["key"].encode())
        self.key = udp.auth.getRsaPrivateFromDer(key, password)

    # game
    def getGames(self) -> dict:
        url = SERVER_URL + "/games/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()

    def getLobbies(self) -> dict:
        url = SERVER_URL + "/lobby/all"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()

    def createLobby(
        self, gameId: int | None = None, gameName: str | None = None
    ) -> dict:
        url = SERVER_URL + "/lobby/create"
        headers = {"Content-Type": "application/json"}
        data = {}
        if gameId:
            data["game-id"] = gameId
        elif gameName:
            data["game-name"] = gameName
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201, r
        return r.json()

    def getLobby(self, lobbyId: int) -> dict:
        url = SERVER_URL + "/lobby/"
        headers = {"Content-Type": "application/json"}
        data = {"lobby-id": lobbyId}
        r = requests.get(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 200
        return r.json()

    def findLobby(self, gameId: int | None = None, gameName: str | None = None) -> dict:
        url = SERVER_URL + "/lobby/find"
        headers = {"Content-Type": "application/json"}
        data = {}
        if gameId:
            data["game-id"] = gameId
        elif gameName:
            data["game-name"] = gameName
        r = requests.get(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 200, r
        return r.json()

    # friends
    def friendLobbies(self) -> dict:
        url = SERVER_URL + "/lobby/friends"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()

    def getFriends(self) -> dict:
        url = SERVER_URL + "/friends/"
        r = requests.get(url, auth=self.auth)
        assert r.status_code == 200, r
        return r.json()

    def addFriend(self, username: str) -> dict:
        url = SERVER_URL + "/friends/add"
        headers = {"Content-Type": "application/json"}
        data = {"username": username}
        r = requests.post(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 201, r
        return r.json()

    def removeFriend(self, username: str) -> bool:
        url = SERVER_URL + "/friend/remove"
        headers = {"Content-Type": "application/json"}
        data = {"username": username}
        r = requests.delete(url, headers=headers, data=json.dumps(data), auth=self.auth)
        assert r.status_code == 204, r
        return True

    # join
    def join(self, lobbyId: int) -> None:
        print(f"\n{bcolors.WARNING}Joining Lobby '{lobbyId}'{bcolors.ENDC}")
        data = self.getLobby(lobbyId)
        if data["lobby-addr"] is not None:
            match data["game-id"]:
                case 1:
                    self.gameClient = RpsClient(
                        (TCP_HOST, C_PORT),
                        data["lobby-addr"],
                        rsaKey=self.key,
                        userId=self.id,
                        username=self.username,
                    )
                    self.gameClient.connect()
                case _:
                    raise ValueError(f"Unknown gameId {data['game-id']}")


def mainloop():
    print(f"{bcolors.HEADER}\nLobby.{bcolors.ENDC}")
    print("1. Login\n2. Register\n3. Quit")
    while True:
        option = input(": ").strip()
        match option:
            case "1":
                _login()
                break
            case "2":
                _register()
                break
            case "3":
                break
            case _:
                print(f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}")


def _register(username: str | None = None, password: str | None = None):
    print(f"{bcolors.HEADER}\nRegister.{bcolors.ENDC}")
    account = None
    while account is None:
        while username is None or password is None:
            try:
                username = input("Username: ").strip()
                password = input("Password: ").strip()
            except:  # noqa: E722
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
        try:
            account = Client.createAccount(username, password)
        except AssertionError:
            print(
                f"{bcolors.FAIL}Account could not be created. Please try again.{bcolors.ENDC}\n"
            )
            username = None
            password = None
    else:
        print(f"Account Created for '{account}'")
        _login(username, password)


def _login(username: str | None = None, password: str | None = None):
    print(f"{bcolors.HEADER}\nLogin.{bcolors.ENDC}")
    token = None
    while token is None:
        while username is None or password is None:
            try:
                username = input("Username: ").strip()
                password = input("Password: ").strip()
            except:  # noqa: E722
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
        try:
            token = Client.getToken(username, password)
        except AssertionError:
            print(
                f"{bcolors.FAIL}Invalid login details. Please try again.{bcolors.ENDC}\n"
            )
            username = None
            password = None
    else:
        client = Client(username, password, token)
        _menu(client)


def _menu(client):
    isRunning = True
    while isRunning:
        print(f"\n{bcolors.HEADER}Main Menu{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}Hello {client.username}.{bcolors.ENDC}")
        while True:
            print(
                "\n1. Manage friends\n2. See available games\n3. Start or join a lobby\n4. Quit"
            )
            option = input(": ").strip()
            match option:
                case "1":
                    _friends(client)
                    break
                case "2":
                    _game(client)
                    break
                case "3":
                    _lobby(client)
                    break
                case "4":
                    isRunning = False
                    break
                case _:
                    print(
                        f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}"
                    )


def _friends(client: Client):
    while True:
        print(f"{bcolors.HEADER}\nFriends.{bcolors.ENDC}")
        friends = client.getFriends()
        friends = "\n\t".join(
            [
                f"{i+1}. {friend['username']}"
                for i, friend in enumerate(friends["friends"])
            ]
        )
        print(f"Friend list: \n\t{friends}")
        print("\n1. Add New Friend\n2. Remove Friend\n3. Return to Main Menu")
        while True:
            option = input(": ").strip()
            match option:
                case "1" | "2":
                    username = input("\nUsername: ").strip()
                    match option:
                        case "1":
                            try:
                                client.addFriend(username)
                                print(
                                    f"\n{bcolors.OKGREEN}Account '{username}' added as friend{bcolors.ENDC}"
                                )
                                break
                            except AssertionError:
                                print(
                                    f"\n{bcolors.FAIL}Error: No such account with username '{username}'.{bcolors.ENDC}"
                                )
                        case "2":
                            try:
                                client.removeFriend(username)
                                print(
                                    f"\n{bcolors.OKGREEN}Account '{username}' removed as friend{bcolors.ENDC}"
                                )
                                break
                            except AssertionError:
                                print(
                                    f"\n{bcolors.FAIL}Error: No such account with username '{username}' in friend list.{bcolors.ENDC}"
                                )
                case "3":
                    return None
                case _:
                    print(
                        f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}"
                    )


def _game(client: Client):
    while True:
        print(f"{bcolors.HEADER}\nGames{bcolors.ENDC}")
        availableGames = client.getGames()
        availableGames = "\n\t".join(
            [f"{id}. {game}" for id, game in availableGames.items()]
        )
        print(f"Available Games: \n\t{availableGames}")
        input("\nPress enter to return to main menu: ")
        return None


def _lobby(client: Client):
    while True:
        print(f"{bcolors.HEADER}\nLobby.{bcolors.ENDC}")
        print(
            "\n1. Matchmaking\n2. See Friends' Lobbies\n3. Join Lobby\n4. Create Lobby\n5. Return to Main Menu"
        )
        while True:
            option = input(": ").strip()
            match option:
                case "1":
                    _matchmaking(client)
                    break
                case "2":
                    _friendsLobbies(client)
                    break
                case "3":
                    _joinLobby(client)
                    break
                case "4":
                    _createLobby(client)
                    break
                case "5":
                    return None
                case _:
                    print(
                        f"{bcolors.FAIL}Error: Invalid input '{option}'.{bcolors.ENDC}"
                    )


def _matchmaking(client: Client):
    print(f"{bcolors.HEADER}\nMatchmaking.{bcolors.ENDC}")
    game = _gameInput(client)
    if game is None:
        return None
    try:
        lobby = client.findLobby(gameName=game)
    except AssertionError:
        lobby = client.createLobby(gameName=game)
    time.sleep(1)
    client.join(lobby["lobby-id"])
    return None


def _friendsLobbies(client: Client):
    print(f"{bcolors.HEADER}\nFriends' Lobbies.{bcolors.ENDC}")
    lobbies = client.friendLobbies()
    lobbiesInfo = lambda lobbies: "\n\t\t".join(
        [
            f"{bcolors.OKCYAN}{lobby['lobby-id']}{bcolors.ENDC}. {lobby['game-name']}"
            for lobby in lobbies
        ]
    )  # noqa: E731
    lobbies = "\n\t".join(
        [
            f"\n\t{i+1}. {account['account']['username']}:\n\t\t{lobbiesInfo(account['lobbies'])}"
            for i, account in enumerate(lobbies)
        ]
    )
    print(f"\nLobbies:{lobbies}")
    print(
        f"Input {bcolors.OKCYAN}Lobby Id{bcolors.ENDC} to Join Friend or Press Enter to Return to Menu."
    )
    while True:
        option = input(": ").strip()
        if option == "":
            return None
        else:
            try:
                option = int(option)
                client.join(option)
                return None
            except ValueError:
                print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")


def _joinLobby(client: Client):
    print(f"{bcolors.HEADER}\nJoin Lobby.{bcolors.ENDC}")
    lobbyId = None
    while lobbyId is None:
        try:
            lobbyId = input("\nLobby Id: ").strip()
            if lobbyId == "":
                return None
            else:
                lobbyId = int(lobbyId)
        except ValueError:
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
    try:
        client.join(lobbyId)
        return None
    except:  # noqa: E722
        return None


def _createLobby(client: Client):
    print(f"{bcolors.HEADER}\nCreate Lobby.{bcolors.ENDC}")
    game = _gameInput(client)
    while True:
        if game is None:
            return None
        try:
            lobby = client.createLobby(gameName=game)
            client.join(lobby["lobby-id"])
            return None
        except AssertionError:
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")


def _gameInput(client: Client) -> str:
    availableGames = client.getGames()
    games = "\n\t".join([f"{id}. {game}" for id, game in availableGames.items()])
    print(f"\nAvailable Games: \n\t{games}")
    game = None
    while game is None or game.lower() not in map(
        lambda x: x.lower(), availableGames.values()
    ):
        try:
            game = input("Game: ").strip()
            if game == "":
                return None
        except:  # noqa: E722
            print(f"{bcolors.FAIL}Error: Invalid input.{bcolors.ENDC}")
    return game


if __name__ == "__main__":
    mainloop()
```

## 9.3.5 .env

```bash
# .env
# udp
S_HOST=127.0.0.1
S_PORT=2024
C_HOST=127.0.0.1
C_PORT=2025
## node
SOCKET_BUFFER_SIZE = 1024
SEND_SLEEP_TIME = 0.1
QUEUE_TIMEOUT = 10
SOCKET_TIMEOUT = 20
## server
HEARTBEAT_MAX_TIME = 120
HEARTBEAT_MIN_TIME = 30
MAX_CLIENTS
## auth
ORG_NAME = Paperclip
COMMON_NAME = 127.0.0.1
## utils
MAX_FRAGMENT_SIZE = 988

# client
TCP_PORT = 5000

# app
FLASK_APP = server
PRUNE_TIME = 58
SECRET_KEY = MyVerySecretKey
SQLALCHEMY_DATABASE_URI = mysql://root:root@localhost:3306/paperclip

# debug
DEBUG = True
```

## 9.3.6 requirements.txt

```txt
cryptography==42.0.5
Flask==3.0.2
Flask-HTTPAuth==4.8.0
Flask-SQLAlchemy==3.1.1
SQLAlchemy-Utils==0.41.2
mysqlclient==2.2.4
requests==2.31.0
PyJWT==2.8.0
pytest==8.1.1
python-dotenv==1.0.1
PyYAML==6.0.1
```

## 9.3.7 test_udp.py

```python
# test_udp
import os
import threading
from random import choice, randint

from udp import C_HOST, C_PORT, auth, error, node, packet, utils


## node
def testNodeSequenceIdLock():
    n = node.Node((C_HOST, C_PORT))

    def test():
        for _ in range(100000):
            n.incrementSequenceId(n.addr)

    threads = [threading.Thread(target=test) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert n.sequenceId == 16960, n.sequenceId


# error
def testErrorCode():
    major = choice([i for i in error.Major])
    minor = error.getMinor(major, randint(0, 2))
    mm = (major, minor)
    e = error.getError(*mm)()
    c = error.getErrorCode(e.__class__)
    assert mm == c, (mm, e, c)


def testErrorPacket():
    h = genRandAttr(packet.Type.ERROR)
    p = packet.ErrorPacket(*h)
    p.data = b"This is a test error"
    p.major = randint(1, 3)
    match p.major:
        case error.Major.CONNECTION:
            p.minor = randint(0, 3)
        case error.Major.DISCONNECT:
            p.minor = randint(0, 2)
        case error.Major.PACKET:
            p.minor = randint(0, 9)
        case _:
            p.minor = 0
    eP = p.pack(p)
    dP = packet.unpack(eP)
    assert p == dP, (p, eP, dP)


# Heartbeat
def testHeartbeatPacket():
    h = genRandAttr(packet.Type.HEARTBEAT)
    p = packet.HeartbeatPacket(*h)
    p.heartbeat = True
    eP = p.pack(p)
    dP = packet.unpack(eP)
    assert p == dP, (p, eP, dP)


# frag
def testDefrag():
    h = genRandAttr()
    data = os.urandom(16)
    p = packet.Packet(*h)
    p.flags[packet.Flag.FRAG.value] = 0
    p.fragment_id = None
    p.fragment_number = None
    p.data = data
    fP = p.fragment()
    dP = fP[0].defragment(fP)
    assert p == dP, (p, fP, dP)


## utils
def testDataCompress(d=os.urandom(16)):
    cD = utils.compressData(d)
    dD = utils.decompressData(cD)
    assert d == dD, (d, cD, dD)


## encrypt
def testPacketEncryption():
    h = genRandAttr()
    p = packet.Packet(*h)
    p.flags[packet.Flag.ENCRYPTED.value] = 1
    d = b"Hello World"
    p.data = d
    localKey = auth.generateEcKey()
    peerKey = auth.generateEcKey()
    localSessionKey = auth.generateSessionKey(localKey, peerKey.public_key())
    peerSessionKey = auth.generateSessionKey(peerKey, localKey.public_key())
    p.encryptData(localSessionKey)
    # print(p.data)
    p.decryptData(peerSessionKey)
    # print(p.data)
    assert d == p.data, (d, p.data)


## auth
def sessionKey():
    localKey = auth.generateEcKey()
    peerKey = auth.generateEcKey()
    localSessionKey = auth.generateSessionKey(localKey, peerKey.public_key())
    peerSessionKey = auth.generateSessionKey(peerKey, localKey.public_key())
    assert localSessionKey == peerSessionKey


def encryptDecrypt(inputText=b"Hello World"):
    localKey = auth.generateEcKey()
    peerKey = auth.generateEcKey()
    sessionKey = auth.generateSessionKey(localKey, peerKey.public_key())
    #
    localCipher, iv = auth.generateCipher(sessionKey)
    cipherText = auth.encryptBytes(localCipher, inputText)
    #
    peerCipher, _ = auth.generateCipher(sessionKey, iv)
    outputText = auth.decryptBytes(peerCipher, cipherText)
    #
    assert inputText == outputText, (inputText, outputText)


## packet
def genRandAttr(t=packet.Type.DEFAULT):
    v, pT, sId = randint(0, 1), t, randint(0, 2**packet.SEQUENCE_ID_SIZE - 1)
    f = [0 for _ in range(packet.FLAGS_SIZE)]
    if randint(0, 1):
        f[packet.Flag.FRAG.value] = 1
        fId, fNum = (
            randint(0, 2**packet.FRAGMENT_ID_SIZE - 1),
            randint(0, 2**packet.FRAGMENT_NUM_SIZE - 1),
        )
    else:
        fId, fNum = None, None
    if randint(0, 1):
        f[packet.Flag.ENCRYPTED.value] = 1
        # iv = randint(0, 2**INIT_VECTOR_SIZE-1)
        iv = auth.generateInitVector()
    else:
        iv = None
    if randint(0, 1):
        f[packet.Flag.CHECKSUM.value] = 1
        c = randint(0, 2**packet.CHECKSUM_SIZE - 1)
    else:
        c = None
    h = (v, pT, f, sId, fId, fNum, iv, c)
    return h


def testAuth():
    pK, c = (
        auth.generateEcKey().public_key(),
        auth.generateUserCertificate(auth.generateRsaKey()),
    )
    pKS, cS = (
        packet.AuthPacket.getPublicKeyBytesSize(pK),
        packet.AuthPacket.getCertificateByteSize(c),
    )
    h = (*genRandAttr(packet.Type.AUTH), pKS, pK, cS, c)
    # static test
    eH = packet.AuthPacket.encodeHeader(*h)
    dH = packet.AuthPacket.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = packet.AuthPacket(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)


def testAck():
    # header
    aId, aB = (
        randint(0, 2**packet.ACK_ID_SIZE - 1),
        [randint(0, 1) for _ in range(packet.ACK_BITS_SIZE)],
    )
    h = (*genRandAttr(packet.Type.ACK), aId, aB)
    # static test
    eH = packet.AckPacket.encodeHeader(*h)
    dH = packet.AckPacket.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = packet.AckPacket(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)


def testAckBits():
    aId, aB = (
        randint(0, 2**packet.ACK_ID_SIZE - 1),
        [randint(0, 1) for _ in range(packet.ACK_BITS_SIZE)],
    )
    eAId, eAB = packet.AckPacket.encodeAckId(aId), packet.AckPacket.encodeAckBits(aB)
    dAId, dAB = packet.AckPacket.decodeAckId(eAId), packet.AckPacket.decodeAckBits(eAB)
    assert (aId, aB) == (dAId, dAB), ((aId, aB), (eAId, eAB), (dAId, dAB))


def testDefault():
    # header
    h = genRandAttr()
    # static test
    eH = packet.Packet.encodeHeader(*h)
    dH = packet.Packet.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = packet.Packet(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)


def testChecksum():
    # checksum
    c = randint(0, 2**packet.CHECKSUM_SIZE - 1)
    eC = packet.Packet.encodeChecksum(c)
    dC = packet.Packet.decodeChecksum(eC)
    assert c == dC, (c, eC, dC)


def testInitVector():
    # init vector
    iv = randint(0, 2**packet.INIT_VECTOR_SIZE - 1)
    eIv = packet.Packet.encodeInitVector(iv)
    dIv = packet.Packet.decodeInitVector(eIv)
    assert iv == dIv, (iv, eIv, dIv)


def testFrag():
    # frag
    fId, fN = (
        randint(0, 2**packet.FRAGMENT_ID_SIZE - 1),
        randint(0, 2**packet.FRAGMENT_NUM_SIZE - 1),
    )
    eFId, eFN = (
        packet.Packet.encodeFragmentId(fId),
        packet.Packet.encodeFragmentNumber(fN),
    )
    dFId, dFN = (
        packet.Packet.decodeFragmentId(eFId),
        packet.Packet.decodeFragmentNumber(eFN),
    )
    assert (fId, fN) == (dFId, dFN), ((fId, fN), (eFId + eFN), (dFId, dFN))


def testFlags():
    # flags
    f = [randint(0, 1) for _ in range(packet.FLAGS_SIZE)]
    eF = packet.Packet.encodeFlags(f)
    dF = packet.Packet.decodeFlags(eF)
    assert f == dF, (f, eF, dF)


def testVersionType():
    # version type
    v, pT = (
        randint(0, 2**packet.VERSION_SIZE - 1),
        packet.Type(randint(0, max(t.value for t in packet.Type))),
    )
    eVt = packet.Packet.encodeVersionType(v, pT)
    dVt = packet.Packet.decodeVersionType(eVt)
    assert (v, pT) == dVt, ((v, pT), eVt, dVt)
```

## 9.3.8 inputimout

Original code by Mitsuo Heijo ([\@johejo](http://github.com/johejo)). Conatins modification to `inputimeout.win_inputimeout` to prevent the automatic appendation of a new line after a timeout.

### 9.3.8.1 __init__.py

```python
from .inputimeout import inputimeout, TimeoutOccurred   # noqa
from .__version__ import (   # noqa
    __version__, __author__, __author_email__, __copyright__, __license__,
    __description__, __title__, __url__,
)
```

### 9.3.8.2 __version__.py

```python
__title__ = 'inputimeout'
__description__ = 'Multi platform standard input with timeout'
__url__ = 'http://github.com/johejo/inutimeout'
__version__ = '1.0.4'
__author__ = 'Mitsuo Heijo'
__author_email__ = 'mitsuo_h@outlook.com'
__license__ = 'MIT'
__copyright__ = 'Copyright 2018 Mitsuo Heijo'
```

### 9.3.8.3 inputimeout.py

```python
# Modified by @HarryWhitehorn on 2024/04/27:
# - Modified win_inputimeout to prevent automatically appending a newline

import sys

DEFAULT_TIMEOUT = 30.0
INTERVAL = 0.05

SP = ' '
CR = '\r'
LF = '\n'
CRLF = CR + LF


class TimeoutOccurred(Exception):
    pass


def echo(string):
    sys.stdout.write(string)
    sys.stdout.flush()


def posix_inputimeout(prompt='', timeout=DEFAULT_TIMEOUT):
    echo(prompt)
    sel = selectors.DefaultSelector()
    sel.register(sys.stdin, selectors.EVENT_READ)
    events = sel.select(timeout)

    if events:
        key, _ = events[0]
        return key.fileobj.readline().rstrip(LF)
    else:
        echo(LF)
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
        raise TimeoutOccurred


def win_inputimeout(prompt='', timeout=DEFAULT_TIMEOUT, newline=False):
    echo(prompt)
    begin = time.monotonic()
    end = begin + timeout
    line = ''

    while time.monotonic() < end:
        if msvcrt.kbhit():
            c = msvcrt.getwche()
            if c in (CR, LF):
                echo(CRLF)
                return line
            if c == '\003':
                raise KeyboardInterrupt
            if c == '\b':
                line = line[:-1]
                cover = SP * len(prompt + line + SP)
                echo(''.join([CR, cover, CR, prompt, line]))
            else:
                line += c
        time.sleep(INTERVAL)
        
    if newline:
        echo(CRLF)
    raise TimeoutOccurred


try:
    import msvcrt

except ImportError:
    import selectors
    import termios

    inputimeout = posix_inputimeout

else:
    import time

    inputimeout = win_inputimeout
```

### 9.3.8.4 LICENSE

```txt
MIT License

Copyright (c) 2017 Mitsuo Heijo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
