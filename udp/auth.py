from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, padding, hmac
from cryptography import x509
from cryptography.x509.oid import NameOID
import os
import datetime

FILE_PATH = r"udp/store/"

def generateRsaKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key

def storeKey(key, filename, password):
    with open(f"{FILE_PATH}{filename}.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))
        
def loadKey(filename, password):
    with open(f"{FILE_PATH}{filename}.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password)
    
def generateCertificate(key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
    ])
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
        # Our certificate will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    
    return cert
    
def storeCertificate(cert, filename):
    # Write our certificate out to disk.
    with open(f"{FILE_PATH}{filename}.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
def loadCertificate(filename):
    with open(f"{FILE_PATH}{filename}.pem", "rb") as f:
        return x509.load_pem_x509_certificate(f.read())
    
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
    