from random import randint, choice
import threading
import os

from udp import S_HOST, S_PORT, C_HOST, C_PORT, node, auth, utils, error, packet

## node
# def testNodeSequenceIdLock():
#     n = node.Node((C_HOST, C_PORT))
#     def test():
#         for _ in range(100000):
#             n.incrementSequenceId(n.addr)
#     threads = [threading.Thread(target=test) for _ in range(10)]
#     for t in threads:
#         t.start()
#     for t in threads:
#         t.join()
#     assert n.sequenceId == 16960, n.sequenceId

# error
def testErrorCode():
    major = choice([i for i in error.Major])
    minor = error.getMinor(major, randint(0,2))
    mm = (major, minor)
    e = error.getError(*mm)()
    c = error.getErrorCode(e)
    assert mm == c, (mm, e, c)
    
    
def testErrorPacket():
    h = genRandAttr(packet.Type.ERROR)
    p = packet.ErrorPacket(*h)
    p.data = b"This is a test error"
    p.major = randint(1, 3)
    match p.major:
        case error.Major.CONNECTION:
            p.minor = randint(0,3)
        case error.Major.DISCONNECT:
            p.minor = randint(0,2)
        case error.Major.PACKET:
            p.minor = randint(0,9)
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
    v, pT, sId = randint(0,1), t, randint(0,2**packet.SEQUENCE_ID_SIZE-1)
    f = [0 for _ in range(packet.FLAGS_SIZE)]
    if randint(0,1):
        f[packet.Flag.FRAG.value] = 1
        fId, fNum = randint(0,2**packet.FRAGMENT_ID_SIZE-1), randint(0,2**packet.FRAGMENT_NUM_SIZE-1)
    else:
        fId, fNum = None, None
    if randint(0,1):
        f[packet.Flag.ENCRYPTED.value] = 1
        # iv = randint(0, 2**INIT_VECTOR_SIZE-1)
        iv = auth.generateInitVector()
    else:
        iv = None
    if randint(0,1):
        f[packet.Flag.CHECKSUM.value] = 1
        c = randint(0,2**packet.CHECKSUM_SIZE-1)
    else:
        c = None
    h = (v, pT, f, sId, fId, fNum, iv, c)
    return h

def testAuth():
    pK, c = auth.generateEcKey().public_key(), auth.generateUserCertificate(auth.generateRsaKey())
    pKS, cS = packet.AuthPacket.getPublicKeyBytesSize(pK), packet.AuthPacket.getCertificateByteSize(c)
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
    aId, aB = randint(0, 2**packet.ACK_ID_SIZE-1), [randint(0,1) for _ in range(packet.ACK_BITS_SIZE)]
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
    aId, aB = randint(0, 2**packet.ACK_ID_SIZE-1), [randint(0,1) for _ in range(packet.ACK_BITS_SIZE)]
    eAId, eAB = packet.AckPacket.encodeAckId(aId), packet.AckPacket.encodeAckBits(aB)
    dAId, dAB = packet.AckPacket.decodeAckId(eAId), packet.AckPacket.decodeAckBits(eAB)
    assert (aId, aB) == (dAId, dAB),  ((aId, aB), (eAId, eAB), (dAId, dAB))

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
    c = randint(0,2**packet.CHECKSUM_SIZE-1)
    eC = packet.Packet.encodeChecksum(c)
    dC = packet.Packet.decodeChecksum(eC)
    assert c == dC, (c, eC, dC)
    
def testInitVector():
    # init vector
    iv = randint(0, 2**packet.INIT_VECTOR_SIZE-1)
    eIv = packet.Packet.encodeInitVector(iv)
    dIv = packet.Packet.decodeInitVector(eIv)
    assert iv == dIv, (iv, eIv, dIv)
    
def testFrag():
    # frag
    fId, fN  = randint(0,2**packet.FRAGMENT_ID_SIZE-1), randint(0,2**packet.FRAGMENT_NUM_SIZE-1)
    eFId, eFN  = packet.Packet.encodeFragmentId(fId), packet.Packet.encodeFragmentNumber(fN)
    dFId, dFN = packet.Packet.decodeFragmentId(eFId), packet.Packet.decodeFragmentNumber(eFN)
    assert (fId, fN) == (dFId, dFN), ((fId, fN), (eFId+eFN), (dFId, dFN))
    
def testFlags():
    # flags
    f = [randint(0,1) for _ in range(packet.FLAGS_SIZE)]
    eF = packet.Packet.encodeFlags(f)
    dF = packet.Packet.decodeFlags(eF)
    assert f == dF, (f, eF, dF)
    
def testVersionType():
    # version type
    v, pT = randint(0,2**packet.VERSION_SIZE-1), packet.Type(randint(0,max(t.value for t in packet.Type)))
    eVt = packet.Packet.encodeVersionType(v,pT)
    dVt = packet.Packet.decodeVersionType(eVt)
    assert (v, pT) == dVt, ((v, pT), eVt, dVt)
    
if __name__ == "__main__":
    testErrorPacket()