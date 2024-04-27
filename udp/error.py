from enum import Enum

class Major(Enum):
    ERROR = 0
    CONNECTION = 1
    DISCONNECT = 2
    PACKET = 3
    
class Minor(Enum): pass
    
class PaperClipError(Exception): """Unknown error"""
    
# connection
class ConnectionErrorCodes(Minor):
    CONNECTION = 0
    NO_SPACE = 1
    CERTIFICATE_INVALID = 2
    FINISH_INVALID = 3

class ConnectionError(PaperClipError):  """Handshake connection could not be finished"""
class NoSpaceError(ConnectionError): """Server has insufficient space to accept new clients"""
class CertificateInvalidError(ConnectionError): """Certificate is invalid / can not be validated"""
class FinishInvalidError(ConnectionError): """Finish is invalid"""

_connectionErrors = {ConnectionErrorCodes.CONNECTION: ConnectionError,
                    ConnectionErrorCodes.NO_SPACE: NoSpaceError,
                    ConnectionErrorCodes.CERTIFICATE_INVALID: CertificateInvalidError,
                    ConnectionErrorCodes.FINISH_INVALID: FinishInvalidError}

def getConnectionError(minor:ConnectionErrorCodes|int) -> ConnectionError:
    try:
        minor = minor if isinstance(minor, Minor) else ConnectionErrorCodes(minor)
        if minor in _connectionErrors:
            return _connectionErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError
    
def getConnectionCode(error:ConnectionError) -> ConnectionErrorCodes:
    try:
        return list(_connectionErrors.keys())[list(_connectionErrors.values()).index(error)]
    except ValueError:
        return PaperClipError

# disconnect
class DisconnectErrorCodes(Minor):
    DISCONNECT = 0
    SERVER_DISCONNECT = 1
    CLIENT_DISCONNECT = 2

class DisconnectError(PaperClipError): """A party is disconnecting"""
class ServerDisconnectError(DisconnectError): """The server is closing"""
class ClientDisconnectError(DisconnectError): """The client is closing"""

_disconnectErrors = {DisconnectErrorCodes.DISCONNECT: DisconnectError, 
                    DisconnectErrorCodes.SERVER_DISCONNECT: ServerDisconnectError, 
                    DisconnectErrorCodes.CLIENT_DISCONNECT: ClientDisconnectError}

def getDisconnectError(minor:DisconnectErrorCodes|int) -> DisconnectError:
    try:
        minor = minor if isinstance(minor, Minor) else DisconnectErrorCodes(minor)
        if minor in _disconnectErrors:
            return _disconnectErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError
    
def getDisconnectCode(error:DisconnectError) -> DisconnectErrorCodes:
    try:
        return list(_disconnectErrors.keys())[list(_disconnectErrors.values()).index(error)]
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

class PacketError(PaperClipError): """Packet cannot be read"""
class VersionError(PacketError): """Packet Version is invalid / does not match expected"""
class PacketTypeError(PacketError): """Packet Type is invalid / unknown"""
class FlagsError(PacketError): """Flags are invalid / unknown"""
class SequenceIdError(PacketError): """Sequence Id is invalid / does not match expected"""
class FragmentIdError(PacketError): """Fragment Id is invalid / unknown"""
class FragmentNumberError(PacketError): """Fragment Number is invalid / unknown"""
class InitVectorError(PacketError): """Init Vector is invalid / unknown i.e. decrypt fail"""
class CompressionError(PacketError): """Decompression fail"""
class ChecksumError(PacketError): """Checksum is invalid / unknown i.e. checksum fail"""

_packetErrors = {PacketErrorCodes.PACKET: PacketError,
                PacketErrorCodes.VERSION: VersionError,
                PacketErrorCodes.PACKET_TYPE: PacketTypeError,
                PacketErrorCodes.FLAGS: FlagsError,
                PacketErrorCodes.SEQUENCE_ID: SequenceIdError,
                PacketErrorCodes.FRAGMENT_ID: FragmentIdError,
                PacketErrorCodes.FRAGMENT_NUMBER: FragmentNumberError,
                PacketErrorCodes.INIT_VECTOR: InitVectorError,
                PacketErrorCodes.COMPRESSION: CompressionError,
                PacketErrorCodes.CHECKSUM: ChecksumError}

def getPacketError(minor:PacketErrorCodes|int) -> PacketError:
    try:
        minor = minor if isinstance(minor, Minor) else PacketErrorCodes(minor)
        if minor in _packetErrors:
            return _packetErrors[minor]
        else:
            return PaperClipError
    except ValueError:
        return PaperClipError
    
def getPacketCode(error:PacketError) -> PacketErrorCodes:
    try:
        return list(_packetErrors.keys())[list(_packetErrors.values()).index(error)]
    except ValueError:
        return PaperClipError

# convenience
def getError(major:Major|int, minor:Minor|int=0) -> PaperClipError:
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
    
def getMinor(major:Major, minor:int) -> Minor:
    match major:
        case Major.CONNECTION:
            return ConnectionErrorCodes(minor)
        case Major.DISCONNECT:
            return DisconnectErrorCodes(minor)
        case Major.PACKET:
            return PacketErrorCodes(minor)
        case _:
            return Minor
        
def getErrorCode(error:PaperClipError) -> tuple[Major,Minor]:
    match error:
        case c if issubclass(c, ConnectionError):
            return (Major.CONNECTION, getConnectionCode(error))
        case d if issubclass(d, DisconnectError):
            return (Major.DISCONNECT, getDisconnectCode(error))
        case p if issubclass(p, PacketError):
            return (Major.PACKET, getPacketCode(error))
        case _:
            return (Major.ERROR, Minor)

if __name__ == "__main__":
    print("e")