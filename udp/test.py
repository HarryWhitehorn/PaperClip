from random import randint
import threading
import utils
import os

from . import Node, auth, S_HOST, S_PORT, C_HOST, C_PORT
from .packet import *

## node
# def nodeSequenceIdLock():
#     n = Node(C_HOST, C_PORT)
#     def test():
#         for _ in range(100000):
#             n.incrementSequenceId()
#     threads = [threading.Thread(target=test) for _ in range(10)]
#     for t in threads:
#         t.start()
#     for t in threads:
#         t.join()
#     assert n.sequenceId == 16960, n.sequenceId

# Heartbeat
def testHeartbeatPacket():
    h = genRandAttr(Type.HEARTBEAT)
    p = HeartbeatPacket(*h)
    p.heartbeat = True
    eP = p.pack(p)
    dP = unpack(eP)
    assert p == dP, (p, eP, dP)

# frag
def testDefrag():
    h = genRandAttr()
    data = os.urandom(16)
    p = Packet(*h)
    p.flags[Flag.FRAG.value] = 0
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
    p = Packet(*h)
    p.flags[Flag.ENCRYPTED.value] = 1
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
def genRandAttr(t=Type.DEFAULT):
    v, pT, sId = randint(0,1), t, randint(0,2**SEQUENCE_ID_SIZE-1)
    f = [0 for _ in range(FLAGS_SIZE)]
    if randint(0,1):
        f[Flag.FRAG.value] = 1
        fId, fNum = randint(0,2**FRAGMENT_ID_SIZE-1), randint(0,2**FRAGMENT_NUM_SIZE-1)
    else:
        fId, fNum = None, None
    if randint(0,1):
        f[Flag.ENCRYPTED.value] = 1
        # iv = randint(0, 2**INIT_VECTOR_SIZE-1)
        iv = auth.generateInitVector()
    else:
        iv = None
    if randint(0,1):
        f[Flag.CHECKSUM.value] = 1
        c = randint(0,2**CHECKSUM_SIZE-1)
    else:
        c = None
    h = (v, pT, f, sId, fId, fNum, iv, c)
    return h

def testAuth():
    pK, c = auth.generateEcKey().public_key(), auth.generateCertificate(auth.generateRsaKey())
    pKS, cS = AuthPacket.getPublicKeyBytesSize(pK), AuthPacket.getCertificateByteSize(c)
    h = (*genRandAttr(Type.AUTH), pKS, pK, cS, c)
    # static test
    eH = AuthPacket.encodeHeader(*h)
    dH = AuthPacket.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = AuthPacket(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)

def testAck():
    # header
    aId, aB = randint(0, 2**ACK_ID_SIZE-1), [randint(0,1) for _ in range(ACK_BITS_SIZE)]
    h = (*genRandAttr(Type.ACK), aId, aB)
    # static test
    eH = AckPacket.encodeHeader(*h)
    dH = AckPacket.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = AckPacket(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)
    
def testAckBits():
    aId, aB = randint(0, 2**ACK_ID_SIZE-1), [randint(0,1) for _ in range(ACK_BITS_SIZE)]
    eAId, eAB = AckPacket.encodeAckId(aId), AckPacket.encodeAckBits(aB)
    dAId, dAB = AckPacket.decodeAckId(eAId), AckPacket.decodeAckBits(eAB)
    assert (aId, aB) == (dAId, dAB),  ((aId, aB), (eAId, eAB), (dAId, dAB))

def testDefault():
    # header
    h = genRandAttr()
    # static test
    eH = Packet.encodeHeader(*h)
    dH = Packet.decodeHeader(eH)[:-1]
    assert h == dH, (h, eH, dH)
    # class tests
    p = Packet(*h)
    eP = p.pack(p)
    dP = p.unpack(eP)
    assert p == dP, (p, eP, dP)
    
def testChecksum():
    # checksum
    c = randint(0,2**CHECKSUM_SIZE-1)
    eC = Packet.encodeChecksum(c)
    dC = Packet.decodeChecksum(eC)
    assert c == dC, (c, eC, dC)
    
def testInitVector():
    # init vector
    iv = randint(0, 2**INIT_VECTOR_SIZE-1)
    eIv = Packet.encodeInitVector(iv)
    dIv = Packet.decodeInitVector(eIv)
    assert iv == dIv, (iv, eIv, dIv)
    
def testFrag():
    # frag
    fId, fN  = randint(0,2**FRAGMENT_ID_SIZE-1), randint(0,2**FRAGMENT_NUM_SIZE-1)
    eFId, eFN  = Packet.encodeFragmentId(fId), Packet.encodeFragmentNumber(fN)
    dFId, dFN = Packet.decodeFragmentId(eFId), Packet.decodeFragmentNumber(eFN)
    assert (fId, fN) == (dFId, dFN), ((fId, fN), (eFId+eFN), (dFId, dFN))
    
def testFlags():
    # flags
    f = [randint(0,1) for _ in range(FLAGS_SIZE)]
    eF = Packet.encodeFlags(f)
    dF = Packet.decodeFlags(eF)
    assert f == dF, (f, eF, dF)
    
def testVersionType():
    # version type
    v, pT = randint(0,2**VERSION_SIZE-1), Type(randint(0,max(t.value for t in Type)))
    eVt = Packet.encodeVersionType(v,pT)
    dVt = Packet.decodeVersionType(eVt)
    assert (v, pT) == dVt, ((v, pT), eVt, dVt)
    
if __name__ == "__main__":
    print(f"\n{'-'*5}START test(s){'-'*5}")
    ALL = False # True
    if True:
        ## node
        # nodeSequenceIdLock()
        ## auth
        sessionKey()
        encryptDecrypt()
        ## packet
        testVersionType()
        testFlags()
        testFrag()
        testInitVector()
        testChecksum()
        testDefault()
        testAckBits()
        testAck()
        testAuth()
        testPacketEncryption()
        testDataCompress()
        testDefrag()
    testHeartbeatPacket()
    print(f"\n{'-'*5}END test(s){'-'*5}")
    