from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate
from enum import Enum
import struct

from . import auth, utils, error, logger

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
ACK_ID_SIZE = SEQUENCE_ID_SIZE # 16
ACK_BITS_SIZE = SEQUENCE_ID_SIZE # 16

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
    
def lazyFlags(*fs:list[Flag]) -> list[int]:
    flags = [0 for _ in range(FLAGS_SIZE)]
    for flag in fs:
        flags[flag.value] = 1
    return flags
     
class Packet:
    version:int = VERSION
    packet_type:Type = Type.DEFAULT
    flags:list[int] = [0 for _ in range(FLAGS_SIZE)]
    sequence_id:int = 0
    fragment_id:int|None = None
    fragment_number:int|None = None
    init_vector:int|None = None
    checksum:int|None = None
    _data:bytes|None = None
    
    def __init__(self, version:int=VERSION, packet_type:Type=Type.DEFAULT, flags:list[int]=[0 for _ in range(FLAGS_SIZE)], sequence_id:int=None, fragment_id:int|None=None, fragment_number:int|None=None, init_vector:int|None=None, checksum:int|None=None, data:bytes|None=None) -> None:
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
    def encryptData(self, session_key:bytes) -> None:
        try:
            self.flags[Flag.ENCRYPTED.value] = 1
            iv = self.init_vector if self.init_vector != None else auth.generateInitVector()
            cipher, iv = auth.generateCipher(session_key, iv)
            self.init_vector = iv
            self.data = auth.encryptBytes(cipher, self.data)
        except Exception as e:
            raise error.InitVectorError(e)
        
    def decryptData(self, session_key:bytes) -> None:
        try:
            if self.flags[Flag.ENCRYPTED.value]:
                cipher = auth.generateCipher(session_key, self.init_vector)[0]
                self.data = auth.decryptBytes(cipher, self.data)
            else:
                # raise ValueError(f"Packet {self} is not flagged as ENCRYPTED ({self.flags}).")
                logger.warning(f"Packet {self} is not flagged as ENCRYPTED ({self.flags}).")
        except Exception as e:
            raise error.InitVectorError(e)
        
    def compressData(self):
        try:
            self.flags[Flag.COMPRESSED.value] = 1
            self.data = utils.compressData(self.data)
        except Exception as e:
            raise error.CompressionError(e)
        
    def decompressData(self):
        try:
            if self.flags[Flag.COMPRESSED.value]:
                self.data = utils.decompressData(self.data)
            else:
                # raise ValueError(f"Packet {self} is not flagged as COMPRESSED ({self.flags}).")
                logger.warning(f"Packet {self} is not flagged as COMPRESSED ({self.flags}).")
        except Exception as e:
            raise error.CompressionError(e)
        
    def setChecksum(self):
        try:
            self.flags[Flag.CHECKSUM.value] = 1
            data = self.data if self.data != None else b""
            self.checksum = utils.generateChecksum(data)
        except Exception as e:
            raise error.ChecksumError(e)
        
    def validateChecksum(self) -> bool:
        try:
            if self.flags[Flag.CHECKSUM.value]:
                data = self.data if self.data != None else b""
                return self.checksum == utils.generateChecksum(data)
            else:
                # raise ValueError(f"Packet {self} is not flagged as CHECKSUM ({self.flags}).")
                logger.warning(f"Packet {self} is not flagged as CHECKSUM ({self.flags}).")
        except Exception as e:
            raise error.ChecksumError(e)
    
    @staticmethod
    def _getHeader(p):
        header = {k:v for k,v in vars(p).items() if not k in ("data","fragment_id","fragment_number")}
        return header
    
    def fragment(self):
        self.flags[Flag.FRAG.value] = 1
        header = Packet._getHeader(self)
        fragData = utils.fragmentData(self.data)
        fragment_number = len(fragData)
        return [self._createFragment(header, fragment_id=i, fragment_number=fragment_number, data=data) for i,data in enumerate(fragData)]
    
    @classmethod
    def _createFragment(cls, header: dict, fragment_id:int, fragment_number:int, data:bytes):
        return cls(**header, fragment_id=fragment_id, fragment_number=fragment_number, data=data)
    
    @classmethod
    def defragment(cls, frags):
        if frags[0].flags[Flag.FRAG.value]:
            header = Packet._getHeader(frags[0])
            header["flags"][Flag.FRAG.value] = 0
            data = utils.defragmentData([frag.data for frag in frags])
            return cls(**header, data=data)
        else:
            # raise ValueError(f"Packet {frags[0]} is not flagged as FRAG ({frags[0].flags}).")
            logger.warning(f"Packet {frags[0]} is not flagged as FRAG ({frags[0].flags}).")

    # dunder
    def __str__(self) -> str:
        try:
            s = self.pack(self)
        except error.PaperClipError:
            s = b""
        data = self.data if self.data != None else b""
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
    def _encodeVersion(version:int) -> int:
        try:
            return version
        except Exception as e:
            raise error.VersionError(e)
    
    @staticmethod
    def _decodeVersion(version:int) -> int:
        try:
            return version
        except Exception as e:
            raise error.VersionError(e)
    
    @staticmethod
    def _encodeType(packet_type:Type) -> int:
        try:
            return packet_type.value
        except Exception as e:
            raise error.PacketTypeError(e)
    
    @staticmethod
    def _decodeType(packet_type:int) -> Type:
        try:
            return Type(packet_type)
        except Exception as e:
            raise error.PacketTypeError(e)
    
    @staticmethod
    def encodeVersionType(version:int, packet_type:Type) -> bytes:
        return struct.pack("!B",(Packet._encodeVersion(version)*16)|Packet._encodeType(packet_type))
        
    @staticmethod
    def decodeVersionType(versionType:bytes) -> tuple[int,Type]:
        versionType = struct.unpack("!B", versionType)[0]
        version = Packet._decodeVersion(versionType >> 4)
        packet_type = Packet._decodeType(versionType & 15)
        return version, packet_type
    
    @staticmethod
    def encodeFlags(flags:list[int]) -> bytes:
        try:
            return struct.pack("!B",int("".join(map(str,flags)),2))
        except Exception as e:
            raise error.FlagsError(e)
    
    @staticmethod
    def decodeFlags(flags:bytes) -> list[int]:
        try:
            flags = struct.unpack("!B",flags)[0]
            flags = [(flags>>i)&1 for i in range(FLAGS_SIZE)]
            flags.reverse()
            return flags
        except Exception as e:
            raise error.FlagsError(e)
    
    @staticmethod
    def encodeSequenceId(sequence_id:int) -> bytes:
        try:
            return struct.pack("!I",sequence_id)
        except Exception as e:
            raise error.SequenceIdError(e)
    
    @staticmethod
    def decodeSequenceId(sequence_id:bytes) -> int:
        try:
            return struct.unpack("!I",sequence_id)[0]
        except Exception as e:
            raise error.SequenceIdError(e)
    
    @staticmethod
    def encodeFragmentId(fragment_id:int) -> bytes:
        try:
            return struct.pack("!B", fragment_id)
        except Exception as e:
            raise error.FragmentIdError(e)
    
    @staticmethod
    def decodeFragmentId(fragment_id:bytes) -> int:
        try:
            return struct.unpack("!B", fragment_id)[0]
        except Exception as e:
            raise error.FragmentIdError(e)
    
    @staticmethod
    def encodeFragmentNumber(fragment_number:int) -> bytes:
        try:
            return struct.pack("!B", fragment_number)
        except Exception as e:
            raise error.FragmentNumberError(e)
    
    @staticmethod
    def decodeFragmentNumber(fragment_number:bytes) -> int:
        try:
            return struct.unpack("!B", fragment_number)[0]
        except Exception as e:
            raise error.FragmentNumberError(e)
        
    @staticmethod
    def encodeInitVector(init_vector:bytes) -> bytes:
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
    def encodeChecksum(checksum:int) -> bytes:
        try:
            return struct.pack("!I", checksum)
        except Exception as e:
            raise error.ChecksumError(e)
        
    @staticmethod
    def decodeChecksum(checksum:bytes) -> int:
        try:
            return struct.unpack("!I", checksum)[0]
        except Exception as e:
            raise error.ChecksumError(e)
    
    @staticmethod
    def encodeHeader(version:int, packet_type:Type,  flags:list[int], sequence_id:int, fragment_id:int|None=None, fragment_number:int|None=None, init_vector:int|None=None, checksum:int|None=None) -> bytes:
        versionType = Packet.encodeVersionType(version, packet_type)
        flags = Packet.encodeFlags(flags)
        sequence_id = Packet.encodeSequenceId(sequence_id)
        fragment_id = Packet.encodeFragmentId(fragment_id) if fragment_id != None else b""
        fragment_number = Packet.encodeFragmentNumber(fragment_number) if fragment_number != None else b""
        init_vector = Packet.encodeInitVector(init_vector) if init_vector != None else b""
        checksum = Packet.encodeChecksum(checksum) if checksum != None else b""
        return versionType + flags + sequence_id + fragment_id + fragment_number + init_vector + checksum
    
    @staticmethod
    def decodeHeader(header:bytes) -> tuple[int, Type, list[int], int, int|None, int|None, int|None, int|None, int]:
        version, packet_type = Packet.decodeVersionType(header[0:1])
        flags = Packet.decodeFlags(header[1:2])
        sequence_id = Packet.decodeSequenceId(header[2:6])
        offset = 6
        if flags[Flag.FRAG.value]:
            fragment_id = Packet.decodeFragmentId(header[offset:offset+1])
            fragment_number = Packet.decodeFragmentNumber(header[offset+1:offset+2])
            offset += 2
        else:
            fragment_id = None
            fragment_number = None
        if flags[Flag.ENCRYPTED.value]:
            init_vector = Packet.decodeInitVector(header[offset:offset+16])
            offset += 16
        else:
            init_vector = None
        if flags[Flag.CHECKSUM.value]:
            checksum = Packet.decodeChecksum(header[offset:offset+4])
            offset += 4
        else:
            checksum = None
        return version, packet_type, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum, offset
    
    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(p.version, p.packet_type, p.flags, p.sequence_id, p.fragment_id, p.fragment_number, p.init_vector, p.checksum)
        return header
    
    @classmethod
    def pack(cls, p) -> bytes:
        header = cls._packHeader(p)
        data = p.data if p.data != None else b""
        return header + data
    
    @classmethod
    def _unpackHeader(cls, bytesP:bytes):
        *header, offset = cls.decodeHeader(bytesP)
        return *header, offset
    
    @classmethod
    def unpack(cls, bytesP:bytes):
        *header, offset = cls._unpackHeader(bytesP)
        data = bytesP[offset:] if offset < len(bytesP) else None
        return cls(*header, data=data)
        
class AckPacket(Packet):
    ack_id:int = 0
    ack_bits:list[int|None] = [None for _ in range(ACK_BITS_SIZE)]
    
    def __init__(self, version: int = VERSION, packet_type:Type.ACK=Type.ACK, flags: list[int] = [0 for _ in range(FLAGS_SIZE)], sequence_id: int = None, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, ack_id:int=None, ack_bits:list[int|None]=[None for _ in range(ACK_BITS_SIZE)], data: bytes | None = None) -> None:
        super().__init__(version, Type.ACK, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum, data)
        self.ack_id = ack_id
        self.ack_bits = ack_bits
        
    # dunder
    def __str__(self) -> str:
        s = self.pack(self)
        data = self.data if self.data != None else b""
        pSize = len(s)
        dSize = len(data)
        if len(data) > 12:
            data = f"{data[:11]}...{str(data[-1:])[1:]}"
        return f"<{self.version}:{self.packet_type.name} {self.sequence_id}:{self.ack_id} {''.join(map(str,self.flags))} {data} [{pSize}:{dSize}]>"
        
    # encode / decode
    @staticmethod
    def encodeAckId(ack_id:int) -> bytes:
        return struct.pack("!I", ack_id)
    
    @staticmethod
    def decodeAckId(ack_id:bytes) -> int:
        return struct.unpack("!I", ack_id)[0]
    
    @staticmethod
    def encodeAckBits(ack_bits:list[int]) -> bytes:
        return struct.pack("!I",int("".join(map(str,(int(bit) if bit!= None else 0 for bit in ack_bits))),2))
    
    @staticmethod
    def decodeAckBits(ack_bits:bytes) -> list[int]:
        ack_bits = struct.unpack("!I",ack_bits)[0]
        ack_bits = [(ack_bits>>i)&1 for i in range(ACK_BITS_SIZE)]
        ack_bits.reverse()
        return ack_bits
    
    @staticmethod
    def encodeHeader(version: int, packet_type: Type, flags: list[int], sequence_id: int, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, ack_id:int=0, ack_bits:list[int|None]=[None for _ in range(ACK_BITS_SIZE)]) -> bytes:
        header = Packet.encodeHeader(version, packet_type, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum)
        ack_id = AckPacket.encodeAckId(ack_id)
        ack_bits = AckPacket.encodeAckBits(ack_bits)
        return header + ack_id + ack_bits
    
    @staticmethod
    def decodeHeader(header: bytes) -> tuple[int, Type, list[int], int, int | None, int | None, int | None, int | None, int, list[int|None], int]:
        *h, offset = Packet.decodeHeader(header)
        ack_id = AckPacket.decodeAckId(header[offset:offset+4])
        offset += 4
        ack_bits = AckPacket.decodeAckBits(header[offset:offset+4])
        offset += 4
        return *h, ack_id, ack_bits, offset
    
    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(p.version, p.packet_type, p.flags, p.sequence_id, p.fragment_id, p.fragment_number, p.init_vector, p.checksum, p.ack_id, p.ack_bits)
        return header

class AuthPacket(Packet):
    _public_key_size:int|None = None
    public_key:EllipticCurvePublicKey|None = None
    _certificate_size:int|None = None
    certificate:Certificate|None = None
    
    def __init__(self, version: int = VERSION, packet_type: Type = Type.AUTH, flags: list[int] = [0 for _ in range(FLAGS_SIZE)], sequence_id: int = None, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, public_key_size:int|None=None, public_key:EllipticCurvePublicKey=None, certificate_size:int|None=None, certificate:Certificate|None=None) -> None:
        super().__init__(version, Type.AUTH, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum, data=None)
        self.public_key_size = public_key_size
        self.public_key = public_key
        self.certificate_size = certificate_size
        self.certificate = certificate
    
    # setter / getter
    @property
    def public_key_size(self) -> int|None:
        if self._public_key_size == None:
            self.public_key_size = AuthPacket.getPublicKeyBytesSize(self.public_key) if self.public_key != None else None
        return self._public_key_size
    
    @public_key_size.setter
    def public_key_size(self, v:int|None) -> None:
        self._public_key_size = v
        
    @staticmethod
    def getPublicKeyBytesSize(publicKey:EllipticCurvePublicKey) -> int:
        return len(auth.getDerFromPublicEc(publicKey))
        
    @property
    def certificate_size(self) -> int|None:
        if self._certificate_size == None:
            self.certificate_size = self.getCertificateByteSize(self.certificate) if self.certificate != None else None
        return self._certificate_size

    @certificate_size.setter
    def certificate_size(self, v:int|None) -> None:
        self._certificate_size = v
    
    @staticmethod
    def getCertificateByteSize(certificate:Certificate) -> int:
        return len(auth.getDerFromCertificate(certificate))
    
    # encode / decode
    @staticmethod
    def encodePublicKeySize(public_key_size:int) -> bytes:
        return struct.pack("!B", public_key_size)
    
    @staticmethod
    def decodePublicKeySize(public_key_size:bytes) -> int:
        return struct.unpack("!B", public_key_size)[0]
    
    @staticmethod
    def encodePublicKey(public_key:EllipticCurvePublicKey) -> bytes:
        return auth.getDerFromPublicEc(public_key)
    
    @staticmethod
    def decodePublicKey(public_key:bytes) -> EllipticCurvePublicKey:
        return auth.getPublicEcFromDer(public_key)
    
    @staticmethod
    def encodeCertificateSize(certificate_size:int) -> bytes:
        return struct.pack("!H", certificate_size)
    
    @staticmethod
    def decodeCertificateSize(certificate_size:bytes) -> int:
        return struct.unpack("!H", certificate_size)[0]
    
    @staticmethod
    def encodeCertificate(certificate:Certificate) -> bytes:
        return auth.getDerFromCertificate(certificate)
    
    @staticmethod
    def decodeCertificate(certificate:bytes) -> Certificate:
        return auth.getCertificateFromDer(certificate)
    
    @staticmethod
    def encodeHeader(version: int, packet_type: Type, flags: list[int], sequence_id: int, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, public_key_size:int|None=None, public_key:EllipticCurvePublicKey|None=None, certificate_size:int|None=None, certificate:Certificate|None=None) -> bytes:
        header = Packet.encodeHeader(version, packet_type, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum)
        public_key_size = AuthPacket.encodePublicKeySize(public_key_size)
        public_key = AuthPacket.encodePublicKey(public_key)
        certificate_size = AuthPacket.encodeCertificateSize(certificate_size) if certificate_size != None else b""
        certificate = AuthPacket.encodeCertificate(certificate) if certificate != None else b""
        return header + public_key_size + public_key + certificate_size + certificate
    
    @staticmethod
    def decodeHeader(header:bytes) -> tuple[int, Type, list[int], int, int|None, int|None, int|None, int|None, int, EllipticCurvePublicKey, int|None, Certificate|None, int]:
        *h, offset = Packet.decodeHeader(header)
        public_key_size = AuthPacket.decodePublicKeySize(header[offset:offset+1])
        offset += 1
        public_key = AuthPacket.decodePublicKey(header[offset:offset+public_key_size])
        offset += public_key_size
        if offset < len(header): # check if more bytes left to decode
            certificate_size = AuthPacket.decodeCertificateSize(header[offset:offset+2])
            offset += 2
            certificate = AuthPacket.decodeCertificate(header[offset:offset+certificate_size])
            offset += certificate_size
        else:
            certificate_size = None
            certificate = None
        return *h, public_key_size, public_key, certificate_size, certificate, offset
    
    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(p.version, p.packet_type, p.flags, p.sequence_id, p.fragment_id, p.fragment_number, p.init_vector, p.checksum, p.public_key_size, p.public_key, p.certificate_size, p.certificate)
        return header
    
    @classmethod
    def unpack(cls, bytesP:bytes):
        *header, offset = cls._unpackHeader(bytesP)
        return cls(*header)
    
class HeartbeatPacket(Packet):
    heartbeat: bool
    def __init__(self, version: int = VERSION, packet_type: Type = Type.HEARTBEAT, flags: list[int] = [0 for _ in range(FLAGS_SIZE)], sequence_id: int = None, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, heartbeat:bool=0, data: bytes | None = None) -> None:
        super().__init__(version, Type.HEARTBEAT, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum, data)
        self.heartbeat = heartbeat
        
    # encode / decode
    @staticmethod
    def encodeHeartbeat(heartbeat:bool) -> bytes:
        return struct.pack("!?", heartbeat)
    
    @staticmethod
    def decodeHeartbeat(heartbeat:bytes) -> bool:
        return struct.unpack("!?", heartbeat)[0]
    
    @staticmethod
    def encodeHeader(version: int, packet_type: Type, flags: list[int], sequence_id: int, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, heartbeat:bool=0) -> bytes:
        header = Packet.encodeHeader(version, packet_type, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum)
        heartbeat = HeartbeatPacket.encodeHeartbeat(heartbeat)
        return header + heartbeat
    
    @staticmethod
    def decodeHeader(header: bytes) -> tuple[int, Type, list[int], int, int | None, int | None, int | None, int | None, bool, int]:
        *h, offset = Packet.decodeHeader(header)
        heartbeat = HeartbeatPacket.decodeHeartbeat(header[offset:offset+1])
        offset += 1
        return *h, heartbeat, offset
    
    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(p.version, p.packet_type, p.flags, p.sequence_id, p.fragment_id, p.fragment_number, p.init_vector, p.checksum, p.heartbeat)
        return header
    
class ErrorPacket(Packet):
    _major: error.Major
    _minor: error.Minor
    def __init__(self, version: int = VERSION, packet_type: Type = Type.ERROR, flags: list[int] = [0 for _ in range(FLAGS_SIZE)], sequence_id: int = None, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, major:error.Major|int=error.Major.ERROR, minor:error.Minor|int=0, data: bytes | None = None) -> None:
        super().__init__(version, Type.ERROR, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum, data)
        self.major = major
        self.minor = minor
        
    @property
    def major(self):
        return self._major
    
    @major.setter
    def major(self, v:error.Major|int):
        if isinstance(v, error.Major):
            self._major = v
        else:
            self._major = error.Major(v)
    
    @property
    def minor(self):
        return self._minor
    
    @minor.setter
    def minor(self, v:error.Minor|int):
        if isinstance(v, error.Minor):
            self._minor = v
        else:
            self._minor = error.getMinor(self.major,v)
            
    # dunder
    def __str__(self) -> str:
        s = self.pack(self)
        data = self.data if self.data != None else b""
        pSize = len(s)
        dSize = len(data)
        # if len(data) > 12:
        #     data = f"{data[:11]}...{str(data[-1:])[1:]}"
        return f"<{self.version}:{self.packet_type.name} {self.sequence_id} {''.join(map(str,self.flags))} {self.major.name}.{self.minor.name}: {data} [{pSize}:{dSize}]>"
    
    # encode / decode
    @staticmethod
    def _encodeMajor(major:error.Major) -> int:
        return major.value
    
    @staticmethod
    def _decodeMajor(major:int) -> error.Major:
        return error.Major(major)
    
    @staticmethod
    def _encodeMinor(minor:error.Minor) -> int:
        return minor.value if minor != error.Minor else 0
    
    @staticmethod
    def _decodeMinor(major:error.Major, minor:int) -> error.Minor:
        return error.getMinor(major, minor)
    
    def encodeMajorMinor(major:int, minor:int) -> bytes:
        majorMinor = (ErrorPacket._encodeMajor(major)*16)|ErrorPacket._encodeMinor(minor)
        return struct.pack("!B", majorMinor)
    
    def decodeMajorMinor(majorMinor:bytes) -> tuple[int, int]:
        majorMinor = struct.unpack("!B", majorMinor)[0]
        major = ErrorPacket._decodeMajor(majorMinor >> 4)
        minor = ErrorPacket._decodeMinor(major, majorMinor & 15)
        return major, minor
    
    @staticmethod
    def encodeHeader(version: int, packet_type: Type, flags: list[int], sequence_id: int, fragment_id: int | None = None, fragment_number: int | None = None, init_vector: int | None = None, checksum: int | None = None, major:int=0, minor:int=0) -> bytes:
        header = Packet.encodeHeader(version, packet_type, flags, sequence_id, fragment_id, fragment_number, init_vector, checksum)
        majorMinor = ErrorPacket.encodeMajorMinor(major, minor)
        return header + majorMinor
    
    @staticmethod
    def decodeHeader(header: bytes) -> tuple[int, Type, list[int], int, int | None, int | None, int | None, int | None, int, int, int]:
        *h, offset = Packet.decodeHeader(header)
        major, minor = ErrorPacket.decodeMajorMinor(header[offset:offset+1])
        offset += 1
        return *h, major, minor, offset
    
    # pack / unpack
    @classmethod
    def _packHeader(cls, p) -> bytes:
        header = cls.encodeHeader(p.version, p.packet_type, p.flags, p.sequence_id, p.fragment_id, p.fragment_number, p.init_vector, p.checksum, p.major, p.minor)
        return header
    
def unpack(rawP):
    packet_type = Packet.decodeVersionType(rawP[0:1])[1]
    match (packet_type):
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
            # raise TypeError(f"Invalid packet type {packet_type}")
            logger.warning(f"Cannot unpack '{packet_type}' due to invalid packet type.")
        
if __name__ == "__main__":
    pass
    