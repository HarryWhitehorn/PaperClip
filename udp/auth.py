from cryptography.hazmat.primitives import serialization, hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding as aPadding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature 
from cryptography import x509
import datetime
import os

FILE_PATH = r"udp/store/"
ORG_NAME = "Paperclip"
COMMON_NAME = "127.0.0.1"

def generateRsaKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key

def getDerFromRsaPrivate(key:rsa.RSAPrivateKey,password:bytes) -> bytes:
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    return der

def getRsaPrivateFromDer(data:bytes, password:bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_der_private_key(data,password=password)
    return key

def getDerFromRsaPublic(key:rsa.RSAPublicKey) -> bytes:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return der
    
def getRsaPublicFromDer(data:bytes) -> rsa.RSAPublicKey:
    key = serialization.load_der_public_key(data)
    return key

# def storeKey(key, filename, password):
#     with open(f"{FILE_PATH}{filename}.pem", "wb") as f:
#         f.write(key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.BestAvailableEncryption(password),
#         ))
        
# def loadKey(filename, password):
#     with open(f"{FILE_PATH}{filename}.pem", "rb") as f:
#         return serialization.load_pem_private_key(f.read(), password)
    
def generateUserCertificate(key, userId:int|str|None=None, username:str|None=None):
    name = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME)]
    if userId != None:
        name.append(x509.NameAttribute(NameOID.USER_ID, str(userId)))
    if username != None:    
        name.append(x509.NameAttribute(NameOID.PSEUDONYM, username))
    subject = issuer = x509.Name(name)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    return cert

def getUserCertificateAttributes(certificate:x509.Certificate) -> list:
    accountId = certificate.subject.get_attributes_for_oid(NameOID.USER_ID)
    accountId = accountId[0].value if len(accountId) > 0 else None
    username = certificate.subject.get_attributes_for_oid(NameOID.PSEUDONYM)
    username = username[0].value if len(username) > 0 else None
    return {"account-id":accountId, "username":username}

def validateCertificate(certificate:x509.Certificate, publicKey:rsa.RSAPublicKey):
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
            certificate.signature_hash_algorithm
        )
    except InvalidSignature:
        return False
    return True
    
    
# def storeCertificate(cert, filename):
#     with open(f"{FILE_PATH}{filename}.pem", "wb") as f:
#         f.write(cert.public_bytes(serialization.Encoding.PEM))
        
# def loadCertificate(filename):
#     with open(f"{FILE_PATH}{filename}.pem", "rb") as f:
#         return x509.load_pem_x509_certificate(f.read())
    
def generateEcKey():
    key = ec.generate_private_key(
        ec.SECP384R1()
    )
    return key

def getDerFromPublicEc(publicKey):
    ecDer = publicKey.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ecDer

def getPublicEcFromDer(publicKeyDer):
    ec_ = serialization.load_der_public_key(publicKeyDer)
    return ec_

def getDerFromCertificate(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)

def getCertificateFromDer(certificateDer):
    return x509.load_der_x509_certificate(certificateDer)

def generateSessionKey(localKey, peerKey):
    sessionSecret = localKey.exchange(ec.ECDH(), peerKey)
    sessionKey = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info=b"handshake data"
    ).derive(sessionSecret)
    return sessionKey

def encryptBytes(cipher, rawBytes, autoPad=True):
    if autoPad:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        rawBytes = padder.update(rawBytes) + padder.finalize()
    encryptor = cipher.encryptor()
    encryptedBytes = encryptor.update(rawBytes) + encryptor.finalize()
    return encryptedBytes

def decryptBytes(cipher:Cipher, encryptedBytes, autoUnpad=True):
    decryptor = cipher.decryptor()
    decryptedBytes = decryptor.update(encryptedBytes) + decryptor.finalize()
    if autoUnpad:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decryptedBytes = unpadder.update(decryptedBytes) + unpadder.finalize()
    return decryptedBytes

def generateInitVector() -> bytes:
    return os.urandom(16)

def generateCipher(sessionKey, iv=generateInitVector()):
    cipher = Cipher(algorithms.AES(sessionKey), modes.CBC(iv))
    return cipher, iv

def generateFinished(sessionKey, finishedLabel, messages):
    hashValue = hashes.Hash(hashes.SHA256())
    hashValue.update(messages)
    hashValue = hashValue.finalize()
    
    prf = hmac.HMAC(sessionKey, hashes.SHA256())
    prf.update(finishedLabel)
    prf.update(hashValue)
    prf = prf.finalize()
    
    return prf
    
if __name__ == "__main__":
    lK = generateEcKey()
    pK = generateEcKey()
    sK = generateSessionKey(lK, pK.public_key())
    prf = generateFinished(sK, b"server", b"\xf0\x0f")
    print(prf)
    print(len(prf))
    assert True
    # ec_ = generateEcKey()
    # assert True
    ##
    # keyOne = generateRsaKey()
    # storeKey(keyOne, "keyOne", b"password1234")
    # print(keyOne)
    # certOne = generateCertificate(keyOne)
    # storeCertificate(certOne, "certOne")
    # print(certOne)
    # certTwo = loadCertificate("certOne")
    # print(certTwo)
    # assert certOne == certTwo
    # assert keyOne.public_key() == certOne.public_key()
    # keyTwo = loadKey("test", b"password1234")
    # print(keyTwo)
    