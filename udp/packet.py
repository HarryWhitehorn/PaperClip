from enum import Enum
import struct
import auth

PACKET_TYPE_SIZE = 1 # 1 bits
FLAGS_SIZE = 4 # 4 bits
SEQUENCE_ID_SIZE = 16 # 16 bits
FRAGMENT_ID_SIZE = 8 # 8 bits
FRAGMENT_NUM_SIZE = 8 # 8 bits
ACK_BITS_SIZE = SEQUENCE_ID_SIZE # 16 bits

class Flag(Enum):
    RELIABLE = 0
    CHECKSUM = 1
    COMPRESSED = 2
    ENCRYPTED = 3
    
class Type(Enum):
    DEFAULT = 0
    FRAG = 1
    ACK = 2
    AUTH = 3

class Packet:
    _packet_type = Type.DEFAULT
    _flags = [0,0,0,0]  #f: [reliable, checksum, compressed, encrypted]
    _sequence_id = 0 

    def __init__(self, seqId, flags=[0,0,0,0], packetType=Type.DEFAULT, data=None):
        self.packet_type = packetType
        self.flags = flags
        self.sequence_id = seqId
        self.data = data
        
    def __str__(self):
        return str(self.pack(self))
    
    def __repr__(self):
        return repr(self.pack(self))
    
    @property
    def packet_type(self):
        return self._packet_type
    
    @packet_type.setter
    def packet_type(self, packetType):
        if isinstance(packetType, Type):
            self._packet_type = packetType
        else:
            raise ValueError(f"packet_type must be in bytes or bytearray with len == {PACKET_TYPE_SIZE}.")
        
    @property
    def sequence_id(self):
        return self._sequence_id
    
    @sequence_id.setter
    def sequence_id(self, seqId):
        if seqId < 2**SEQUENCE_ID_SIZE:
            self._sequence_id = seqId
        else:
            raise ValueError(f"sequence_id must be in bytes or bytearray with len == {SEQUENCE_ID_SIZE}.")
        
    @property
    def flags(self):
        return self._flags
    
    @flags.setter
    def flags(self, fs):
        if len(fs) == FLAGS_SIZE:
            self._flags = fs
        else:
            raise ValueError(f"flags must be bool[] with len() == {FLAGS_SIZE}.")
        
    @classmethod
    def _packHeader(cls, p):
        header = []
        packedTypeFlags = (16 * p.packet_type.value) | int(''.join(map(str,p.flags)),2)
        header.append(struct.pack("!B",packedTypeFlags))
        header.append(struct.pack("!H",p.sequence_id))
        return header
    
    @classmethod
    def pack(cls, p):
        header = cls._packHeader(p)
        if p.data != None:
            if type(p.data) == str:
                header.append(bytes(p.data,"UTF-8"))
            elif type(p.data) == bytes:
                header.append(p.data)
            else:
                raise TypeError(f"Unknown data type. Cannot encode {p.data} of type {type(p.data)}.")
        return b"".join(header)
    
    @classmethod
    def _unpackHeader(cls, rawP):
        packedTypeFlags = rawP[0]
        packet_type = Type(packedTypeFlags >> 4)
        flags = (packedTypeFlags & 15)
        flags = [(flags>>i)&1 for i in range(4)]
        flags.reverse()
        sequence_id = struct.unpack("!H",rawP[1:3])[0]
        return sequence_id, flags, packet_type
    
    @classmethod
    def unpack(cls, rawP):
        header = cls._unpackHeader(rawP)
        data = rawP[3:].decode()
        return cls(*header, data)
    
class FragPacket(Packet):
    _packet_type = Type.FRAG
    _fragment_id = None 
    _fragment_num = None
    
    def __init__(self, seqId, flags=[0, 0, 0, 0], fragId=None, fragNum=None, data=None):
        super().__init__(seqId, flags, Type.FRAG, data)
        self.fragment_id = fragId
        self.fragment_num = fragNum
    
    @property
    def fragment_id(self):
        return self._fragment_id
    
    @fragment_id.setter
    def fragment_id(self, fragId):
        if fragId != None:
            if fragId < 2**FRAGMENT_ID_SIZE:
                self._fragment_id = fragId
            else:
                raise ValueError(f"fragment_id must be int < {2**FRAGMENT_ID_SIZE}.")
        else:
            self._fragment_id = None
        
    @property
    def fragment_num(self):
        return self._fragment_num
    
    @fragment_num.setter
    def fragment_num(self, fragNum):
        if fragNum != None:
            if fragNum < 2**FRAGMENT_NUM_SIZE:
                self._fragment_num = fragNum
            else:
                raise ValueError(f"fragment_num must be int < {2**FRAGMENT_NUM_SIZE}.")
        else:
            self._fragment_num = None
            
    @classmethod
    def _packHeader(cls, p):
        header = super()._packHeader(p)
        header.append(struct.pack("!B",p.fragment_id))
        header.append(struct.pack("!B",p.fragment_num))
        return header
    
    @classmethod
    def _unpackHeader(cls, rawP):
        header = super()._unpackHeader(rawP)
        fragment_id, fragment_num = struct.unpack("!BB",rawP[3:5])
        return *header[:2], fragment_id, fragment_num
    
    @classmethod
    def unpack(cls, rawP):
        header = cls._unpackHeader(rawP)
        data = rawP[5:].decode()
        return cls(*header, data)

class AckPacket(Packet):
    _ack_id = 0
    _ack_bits = [None for _ in range(ACK_BITS_SIZE)]
    
    def __init__(self, seqId, ackId, ackBits=[None for _ in range(ACK_BITS_SIZE)], flags=[0, 0, 0, 0]):
        super().__init__(seqId, flags, Type.ACK)
        self.ack_id = ackId
        self.ack_bits = ackBits
        
    @property
    def ack_id(self):
        return self._ack_id
    
    @ack_id.setter
    def ack_id(self, v):
        self._ack_id = v
        
    @property
    def ack_bits(self):
        return self._ack_bits
    
    @ack_bits.setter
    def ack_bits(self, v):
        self._ack_bits = v
        
    @classmethod
    def _packHeader(cls, p):
        header = super()._packHeader(p)
        header.append(struct.pack("!H",p.ack_id))
        header.append(struct.pack("!H",int("".join(map(str,[int(bit) if bit!=None else 0 for bit in p.ack_bits])),2)))
        return header
    
    @classmethod
    def _unpackHeader(cls, rawP):
        header = super()._unpackHeader(rawP)
        ack_id, ack_bits = struct.unpack("!HH",rawP[3:7])
        ack_bits = [(ack_bits>>i)&1 for i in range(ACK_BITS_SIZE)]
        ack_bits.reverse()
        return header[0], ack_id, ack_bits, header[1]
    
    @classmethod
    def unpack(cls, rawP):
        header = cls._unpackHeader(rawP)
        return cls(*header)
    
class AuthPacket(Packet):
    def __init__(self, seqId, cert, publicEc, finished=b"\x00"*32, flags=[0, 0, 0, 0]):
        super().__init__(seqId, flags, Type.AUTH)
        self.cert = cert
        self.publicEc = publicEc
        self.finished = finished
        
    @classmethod
    def _packHeader(cls, p):
        header = super()._packHeader(p)
        certBytes = p.cert.public_bytes(auth.serialization.Encoding.DER)
        ecBytes = auth.getDerFromPublicEc(p.publicEc)
        header.append(struct.pack("!H", len(certBytes)))
        header.append(struct.pack("!B", len(ecBytes)))
        header.append(certBytes)
        header.append(ecBytes)
        header.append(p.finished)
        return header
        
    @classmethod
    def _unpackHeader(cls, rawP):
        header = super()._unpackHeader(rawP)
        OFFSET = 6
        certSize, ecSize = struct.unpack("!HB", rawP[3:OFFSET])
        certBytes = rawP[OFFSET:certSize+OFFSET]
        cert = auth.x509.load_der_x509_certificate(certBytes)
        OFFSET += certSize
        ecBytes = rawP[OFFSET:ecSize+OFFSET]
        publicEc = auth.getPublicEcFromDer(ecBytes)
        OFFSET += ecSize
        finished = rawP[OFFSET:OFFSET+32]
        return header[0], cert, publicEc, finished, header[1] 
    
    @classmethod
    def unpack(cls, rawP):
        header = cls._unpackHeader(rawP)
        return cls(*header)
    

def unpack(rawP):
    packet_type = Type(rawP[0] >> 4)
    match (packet_type):
        case Type.DEFAULT:
            return Packet.unpack(rawP)
        case Type.FRAG:
            return FragPacket.unpack(rawP)
        case Type.ACK:
            return AckPacket.unpack(rawP)
        case Type.AUTH:
            return  AuthPacket.unpack(rawP)
        case _:
            raise TypeError(f"Invalid packet type {packet_type}")
            pass
    
        
        
if __name__ == "__main__":
    # p = Packet()
    # p.packet_type = Type.FRAG
    # print(p.pack())
    # print("e")
    # p = FragPacket(65526, [0,0,1,1], 10, 40)#self.sequenceId)
    p = AckPacket(12,15,[i%2 for i in range(ACK_BITS_SIZE)])
    # p = FragPacket(1,fragId=1,fragNum=8)
    # p.data = "PING"
    b = p.pack(p)
    pp = unpack(b)
    print(p,"\t",b,"\t",p)
    assert str(p) == str(b) == str(pp)