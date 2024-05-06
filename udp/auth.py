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
