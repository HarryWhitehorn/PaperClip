# 5 Results

## 5.3 Design

### 5.3.1 Packet Specification

A formal *Packet Specification* was created laying out the different packet types, their flags and flags behaviour and well as various other headers. Additionally, the *Packet Specification* describes a handshake.

The *Packet Specification* is omitted from results section for clarity but is available in full in the documents appendices [`Appendices 9.4`].

### 5.3.2 Database Models

A `ERD` was created defining the structure of the various database models and their relationships.

![Database Models ERD](ERD\ERD.jpg)

### 5.3.3 API Specification

A formal *API Specification* was created describing the various endpoints the `RESTful` `API` `Server`.

The *API Specification* is omitted from results section for clarity but is available in full in the documents appendices [`Appendices 9.5`].

## 5.4 Implementation

### 5.4.1 Iteration 1

#### 5.4.1.1 Packet Specification Implementation

Each packet type (defined in the packet spec) is implemented as its own class. All packet classes inherit from a base `Packet` equivalent to the `DEFAULT` packet. The packet classes contain the defined fields as well as static methods to convert from a class instance into bytes (*pack*) and vice versa (*unpack*). The `struct` package allows for converting to and from some integer value into a fixed size bytes with the appropriate padding as well as handling endianness (as `UDP` uses big-endian). Most class fields are either already integers or can be easily represented as an integer (enum, boolean) but some fields (e.g. public key, certificate, data) require more complex casting. Additionally, the `udp.packet` script includes various `Enum`s containing definitions of the `Flag`s and packet `Type`s and `CONST`s which define the sizes (in bits) of the headers. These are both used in generation of default (empty) header values as well as a reference in other scripts.

```python
from enum import Enum
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
```

---

#### 5.4.1.2 UDP Node

Both the `udp.Client` and `udp.Server` classes inherit from a `udp.Node` base class.

##### 5.4.1.2.1 Sending Data

The `Node` class provides methods for sending `Packets` using `socket.socket`. The `sendPacket` method takes an address and a packet instance and dispatches the packed packet to the given host.

```python
def sendPacket(self, addr:tuple[str, int], p:packet.Packet) -> None:
        self.socket.sendto(p.pack(p), (addr[0],addr[1]))
```

The `sendPacket` method is typically not directly called, with relevant send methods existing for each packet type. As `Node` is responsible for keeping an internal `sequenceId`, is able to set each packet and then increment its record.

```python
def sendDefault(self, addr:tuple[str, int], data:bytes|None=None) -> None:
        p = packet.Packet(sequence_id=self.sequenceId, data=data)
        self.sequenceId += 1
        self.sendPacket(addr, p)
```

##### 5.4.1.2.2 Receiving Data

The `Node` class also provides a method for receiving packets from the `socket`. This allows for packets to be packed into an instance before they are returned.

```python
def receivePacket(self) -> tuple[packet.Packet, tuple[str, int]]:
    data, addr = self.socket.recvfrom(BUFFER_SIZE)
    p = packet.unpack(data)
    return p, addr
```

##### 5.4.1.2.3 UDP Client

The `Client` also includes a target address and overrides the `Node`'s send methods to set the destination to be its target address. The `addr` field is still included in the method so that function calls from `Node` do not break.

```python
def sendDefault(self, addr:tuple[str,int]=None, data:bytes|None=None):
    return super().queueDefault(self.targetAddr, data=data)
```

##### 5.4.1.2.4 UDP Server

The `Server` is initially passive, only replying to incoming packets from a client.

```python
def mainloop(self):
    while True:
        p, addr = self.receivePacket()
        # logic to process and reply (if needed)
        # e.g. self.sendDefault(addr, data=b"Hello Client")
```

---

#### 5.4.1.3 DEFAULT Packet

The `DEFAULT` packet takes a list of booleans flags in addition to a data field. The flags field defaults to any list of `False` if no flags are specified.

```python
def sendDefault(self, addr:tuple[str, int], flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)], data:bytes|None=None) -> None:
    p = packet.Packet(sequence_id=self.sequenceId, flags=flags, data=data)
    self.sequenceId += 1
    self.sendPacket(addr, p)
```

```python
def receiveDefault(p: packet.Packet, addr: tuple[str, int]):
    pass
```

---

#### 5.4.1.4 Threading

In order to be able to send and receive packets simultaneously both actions are contained in a `threading.Thread`.

##### 5.4.1.4.1 Thread Safety

The `GIL` does not protect against such interaction as the `+=` operator. As such the `sequenceId` variable must be incremented using a `threading.Lock` so that all threads can increment the `sequenceId` safely.

```python
def incrementSequenceId(self) -> None:
    with self.sequenceIdLock:
        self.sequenceId += 1
```

The `threading` module also provides the `Event` class. This allows easy communication between threads and is used for the `isRunning` field to stop all threads whenever any thread resets the `Event` to `False`.

##### 5.4.1.4.2 Inbound Thread

The `inboundThread` field is defined as `Thread(name="Inbound", target=self.listen, daemon=True)` on a `Node`'s `__init__`.

The `listen` method waits for an incoming package and yield to the `receive` method. This happens in a loop until `isRunning` is reset.

```python
def listen(self):
    while self.isRunning.is_set():
        p, addr = self.receivePacket()
        self.receive(p, addr)
```

The `receive` method is responsible for passing the package to the appropriate packet type receive method.

```python
def receive(self, p: packet.Packet, addr: tuple[str, int]):
    if p is not None:
        match (p.packet_type):
            case packet.Type.DEFAULT:
                return self.receiveDefault(p, addr)
            # other packet type cases omitted for clarity
            case _:
                raise TypeError(f"Unknown packet type '{p.packet_type}' for packet {p}")
```

The `Server` uses it own `listen` method. It uses this to only allow certain packets depending on the state of the client's handshake. If the client has not yet initiated handshake, and thus does not exist, all packets other than `AUTH` are dropped. If a client has started, and thus exists, but has not completed the handshake only `AUTH` and `ACK` packets are passed. The `Server` otherwise accepts all packets from a *connected* client (i.e. a client with a completed handshake).

```python
def listen(self) -> None:
    while self.isRunning.is_set():
        p, addr = self.receivePacket()
        if p is not None and addr is not None:
            if self.checkClientExists(addr):  # client exists
                if self.getHandshake(addr):  # client handshake complete => allow all packet types
                    self.receive(p, addr)
                else:
                    if p.packet_type in (packet.Type.AUTH, packet.Type.ACK):  # client handshake incomplete => drop all non-AUTH | non-ACK packets
                        self.receive(p, addr)
            else:
                if p.packet_type in (packet.Type.AUTH):  # client not exists => drop all non-AUTH packets
                    self.receive(p, addr)
```

##### 5.4.1.4.3 Outbound Thread

The `outboundThread` field is defined as `Thread(name=f"Outbound", target=self.sendQueue, daemon=True)` on a `Node`'s `__init__`. In order for the the `sendQueue` method to be able to send packages they first need to be added to a `queue.Queue`. A `Queue` is a thread-safe data structure with built in locking, allowing for multiple threads to safely add and remove data in the same variable.

```python
def sendQueue(self):
        while self.isRunning.is_set():
            addr, p = self.queue.get()
            self.sendPacket(addr, p)
            self.queue.task_done()
            time.sleep(SLEEP_TIME)  # some small time delay
```

The send methods are replaced by their receptive queue methods. Instead of sending the packet they instead yield to the `queuePacket` method.

```python
def queueDefault(self, addr:tuple[str, int], data:bytes|None=None) -> None:
    p = packet.Packet(sequence_id=self.sequenceId, data=data)
    self.incrementSequenceId()
    self.queuePacket(addr, p)
```

The `queuePacket` method, in turn, appends the packet (with the relent destination address) to the queue. This method is also used to apply the reliant flag behavior(s).

```python
def queuePacket(self, addr: tuple[str, int], p: packet.Packet) -> None:
    # logic for flags omitted
    self.queue.put((addr, p))
```

##### 5.4.1.4.4 Server Clients

The `Server`, now being threaded, is able to accept multiple clients. Whenever a new handshake is started by a client, a new `Node` is created and added to a dictionary field `clients` (using the client address as the key). The `Node` uses the server's socket to send replies to a client and as such the `Node` class is refactored to take a `socket` as well as a `Lock`. The `Lock` is used whenever a packet is sent, to ensure thread-safety. Using a `Node` for tracking clients allows for each client connection to have its own `sequenceId`,  (as well as `sessionKey`, `ecKey`, etc. described in later iterations).

```python
def makeClient(self, clientAddr: tuple[str, int]) -> None:
        c = node.Node(
            clientAddr,
            sendLock=self.sendLock,
            socket=self.socket,
        )
        c.outboundThread.start()
        with self.clientsLock:
            self.clients[clientAddr] = c
```

Additionally, all `Node` fields are refactored to use getter and setters taking an addr. This allows the `Server` class to override the setter and getters to instead return the relevant field from client in the dictionary. The `Server` also uses a `Lock` when retrieving client attributes.

```python
def getSequenceId(self, clientAddr: tuple[str, int]) -> int | None:
        with self.clientsLock:
            return (
                self.clients[clientAddr].sequenceId
                if clientAddr in self.clients
                else None
            )
```

### 5.4.2 Iteration 2

#### 5.4.2.1 RELIABLE Flag and ACK Packets

##### 5.4.2.1.1 Sending a RELIABLE packet

When queuing a `RELIABLE` packet the `Node` sets the relevant sentAckBit to false before adding to the send queue.

```python
def queuePacket(self, addr: tuple[str, int], p: packet.Packet) -> None:
    if p.flags[packet.Flag.RELIABLE.value]:
        self.setSentAckBit(addr, p.sequence_id, False) # set relevant ack bit to False
    self.queue.put((addr, p))
```

After a `Node` sends a packet with the `RELIABLE` flag set it appends the packet back to the end of the queue. The next time the `Node` goes to send the packet it first checks against its record of received ACKed packets. If the packet has already been ACK, the recipient has given confirmation of receival and the packet does not need to be resent. This helps to mitigate against packet loss as *critical* packets which are marked as `RELIABLE` will be resent until the `Node` is confident that that the recipient has received it.

```python
def sendQueue(self):
    while self.isRunning.is_set():
        addr, p = self.queue.get()
        if p.flags[packet.Flag.RELIABLE.value]:
            if self.getSentAckBit(addr, p): # checks if ACKed
                self.queue.task_done()
                continue # skips
            else:
                self.sendPacket(addr, p) # sends
                self.queue.task_done()
                self.queue.put((addr, p)) # re-adds to the queue
        else:
            self.sendPacket(addr, p)
            self.queue.task_done()
        time.sleep(SEND_SLEEP_TIME)
```

##### 5.4.2.1.2 Receiving a RELIABLE packet

When a `Node` receives a packet with the `RELIABLE` flag set, in addition to processing the packet as normal, the `Node` appends an `ACK` packets to its queue. The `ACK` package's `ACK ID` is set to the `Sequence ID` of the incoming package. The `Node` also keeps a record of sent `ACK` packet's to ensure that any repeat packets do not propagate to the *application layer*.

```python
def handleReliable(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
        if p.flags[packet.Flag.RELIABLE.value]:
            self.setRecvAckBit(addr, p.sequence_id, True) # set relevant recv bit
            self.queueACK(addr, p.sequence_id) # queues and ACK
            return True
        else:
            return False
```

The `handleReliable` method is called by the `handleFlags` method. This method is responsible for processing all flags *before* the `Node` attempts to process the packet instance.

```python
def handleFlags(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
    self.handleReliable(p, addr)
    return True
```

As such, the `receive` method is modified to first handle flags before processing.

```python
def receive(self, p: packet.Packet, addr: tuple[str, int]):
    if p is not None:
        if self.handleFlags(p, addr):
            match (p.packet_type):
                # packet type cases omitted for clarity
                case _:
                    raise TypeError(f"Unknown packet type '{p.packet_type}' for packet {p}")
```

##### 5.4.2.1.3 Sending an ACK Packet

In addition to all of the fields used to queue a `DEFAULT` packet, the `ACK` packet also takes an `ackId` representing the packet to which the `ACK` is acknowledging.

```python
def queueACK(self, addr: tuple[str, int], ackId: int, flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)], data: bytes | None = None) -> None:
        p = packet.AckPacket(
            sequence_id=self.getSequenceId(addr),
            flags=flags,
            ack_id=ackId,
            data=data,
        )
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)
```

##### 5.4.2.1.4 Receiving an ACK Packet

When a `Node` receives an `ACK` packet is sets the relevant `ACK ID` in is record of received ACKed packets to `true`, thus preventing resending a confirmed packet.

```python
def receiveAck(self, p: packet.AckPacket, addr: tuple[str, int]) -> tuple[packet.Packet, tuple[str, int]]:
    self.setSentAckBit(addr, p.ack_id, True)
    return (p, addr)
```

---

#### 5.4.2.2 AUTH Packets

The `X.509` certificates are generated in `udp.auth` taking a RSA private key for signing and are self-signed (i.e the subject is also the issuer).

```python
def generateUserCertificate(key) -> x509.Certificate:
    name = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME), # ORG_NAME defined as const e.g. "Paperclip"
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME), # COMMON_NAME defined as const e.g. "127.0.0.1"
    ]
    subject = issuer = x509.Name(name) # self signed
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1) # valid for one day
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), # self signed
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert
```

The key and certificate are converted to and from `DER` bytes format when packing and unpacking.

```python
def getDerFromPublicEc(publicKey: ec.EllipticCurvePublicKey) -> bytes:
    ecDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ecDer
```

```python
def getPublicEcFromDer(publicKeyDer: bytes) -> ec.EllipticCurvePublicKey:
    ec_ = serialization.load_der_public_key(publicKeyDer)
    return ec_
```

##### 5.4.2.2.1 Sending an AUTH Packet

The `queueAuth` packet takes the additional fields of a certificate and a public key.

```python
def queueAuth(self, addr: tuple[str, int], cert: Certificate, publicEc: auth.ec.EllipticCurvePublicKey) -> None:
    p = packet.AuthPacket(
        sequence_id=self.getSequenceId(addr), certificate=cert, public_key=publicEc
    )
    self.incrementSequenceId(addr)
    self.queuePacket(addr, p)
```

---

##### 5.4.2.2.2 Receiving an AUTH Packet

The base `Node` class contains a `receiveAuth` method exclusively for use in overriding.

```python
def receiveAuth(self, p: packet.AuthPacket, addr: tuple[str, int]) -> tuple[packet.Packet, tuple[str, int]]:
        raise NotImplementedError(
            "Node should not receive auth. A child class must overriding."
        )
```

The `Server` overrides this method with the logic for handling a handshake. The `Client` class, however, does not make use of this method as it handles all AUTH packets during its `connect` method.

---

#### 5.4.2.3 Handshake

The handshake is implemented according to the packet specification. The session key is generated with a `ECDH` key exchange in `udp.auth`.

```python
def generateSessionKey(localKey: ec.EllipticCurvePrivateKey, peerKey: ec.EllipticCurvePublicKey) -> bytes:
    sessionSecret = localKey.exchange(ec.ECDH(), peerKey)
    sessionKey = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data"
    ).derive(sessionSecret)
    return sessionKey
```

The `Finished` is computed by calculating the `HMAC` of the finishedLabel and messages using the session key.

```python
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

##### 5.4.2.3.1 Client Handshake

The `Client` is responsible for starting the handshake using the `connect` method. It starts by starting the `outboundThread` so it is able to send packets. It is then able to send a `AUTH` packet. The client then waits to receive both the `AUTH` and `ACK` packet from the `Server`.

When the `AUTH` packet is received the `Client` first generates the session key. It is then able to compute the `Finished` which is sent as the data field of an `ACK` packet. It also checks the validity of the `Server`'s certificate, aborting the connection attempt on a failure.

When both the `ACK` and `AUTH` packets are received the `Client` checks the validity of the `Finished` by checking its version of `Finished` against the contents of the `ACK` packet. On a failure, the connection is aborted. On a success, the `Client` starts the `inboundThread` and the connection is considered complete.

```python
def connect(self) -> None:
    self.outboundThread.start() # start outbound
    self.queueAuth(self.targetAddr, self.cert, self.ecKey.public_key()) # send auth
    authPacket = None
    ackPacket = None
    while True:
        p, addr = self.receivePacket()
        if p is not None:
            # logic
            if p.packet_type == packet.Type.AUTH: # AUTH packet -> generate session key, validate certificate, queueFinished
                authPacket = p
                self.sessionKey = auth.generateSessionKey(
                    self.ecKey, p.public_key
                )
                if not self.validateCertificate(p.certificate):
                    # certificate not valid
                    # abort
                    break
                self.queueFinished(
                    self.targetAddr, p.sequence_id, self.sessionKey
                )
            elif p.packet_type == packet.Type.ACK: # ACK packet
                ackPacket = p
                self.receiveAck(p, addr)
            if authPacket is not None and ackPacket is not None: # wait until both parts received
                break
        else:
            # Server not responsive
            # abort
            break
    if self.validateHandshake(ackPacket.data): # check finished
        # success
        self.inboundThread.start() # start inbound
    else:
        # abort
```

##### 5.4.2.3.2 Server Handshake

The `Server`, being a passive listener to the handshake, overrides `receiveAuth` to respond accordingly. The handshake logic varies slightly depending on if the client is a new or existing client (i.e. reconnecting).

If the client is new, the `Server` first ensures it has space (set by the `maxClients` field) and then creates a new client.

If a new client has been created or the client already exists, the `Server` first checks the validity of the client's certificate. The `Server` then regenerates the `Node`'s `ecKey` to be used in generating the sessionKey. It is then able to send both the reply `AUTH` and `ACK` (containing the generated `Finished`).

```python
def receiveAuth(self, p: packet.AuthPacket, addr: tuple[str, int]) -> tuple[packet.AuthPacket, tuple[str, int]]:
    if addr not in self.clients:  # new client
        if self.isNotFull():  # check space
            valid, accountId = self.validateCertificate(p.certificate)
            if not valid:
                # invalid certificate
                # abort
                return 
            else:
                self.makeClient(addr, p.certificate, accountId)
                self.regenerateEcKey(addr)
                sessionKey = auth.generateSessionKey( 
                    self.getEcKey(addr), p.public_key
                )
                self.setSessionKey(addr, sessionKey) # sets client sessionKey for later reference
                self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
        else:
            # no space
            # abort
            return
    else:
        sessionKey = auth.generateSessionKey(self.getEcKey(addr), p.public_key)
    if addr in self.clients: # existing client
        if self.getSessionKey(addr) != sessionKey:  # new client sessionKey
            valid, accountId = self.validateCertificate(p.certificate)
            if not valid:
                # invalid certificate
                # abort
                # remove client
                return
            else:
                self.regenerateEcKey(addr)
                sessionKey = auth.generateSessionKey(
                    self.getEcKey(addr), p.public_key
                )
                self.setSessionKey(addr, sessionKey)  # make new session key
                self.queueAuth(addr, self.cert, self.getEcKey(addr).public_key())
                self.queueFinished(addr, p.sequence_id, self.getSessionKey(addr))
    return (p, addr)
```

When the `Server` receives an `ACK` packet the server it checks that the packet's data matches the generated `Finished`. If the check fails, the connection is aborted and the handshake is not set to complete.

```python
def receiveAck(self, p: packet.AckPacket, addr: tuple[str, int]) -> None:
        super().receiveAck(p, addr)
        if p.data is not None and not self.getHandshake(addr):  # ack has payload & client has not completed handshake => validate handshake
            if not self.validateHandshake(addr, p.data): # checks and sets the clients handshake
                # invalid finish
                # abort
                return
            else:
                # success
                pass
```

---

#### 5.4.2.4 Flags

All flags behaviors are executed on a packet (where set) before sending and after receiving meaning that the data yielded to the *application* layer is as it was originally set.

##### 5.4.2.4.1 ENCRYPT

Encryption and decryption is performed using `AES` with the session key and a 16-bit init vector.

```python
def generateCipher(sessionKey: bytes, iv: bytes = generateInitVector()) -> tuple[Cipher, bytes]:
    cipher = Cipher(algorithms.AES(sessionKey), modes.CBC(iv))
    return cipher, iv
```

###### 5.4.2.4.1.1 Encryption

When a `Node` goes to queue a packet with the `ENCRYPT` flag set it calls `p.encryptData(self.getSessionKey(addr))` (where `p` is the packet). The `encryptData` method generates an `init vector` and subsequent `cipher` before performing the encryption on the data.

```python
def encryptData(self, session_key: bytes) -> None:
    self.flags[Flag.ENCRYPTED.value] = 1 # ensure flag set
    iv = (
        self.init_vector
        if self.init_vector is not None
        else auth.generateInitVector() # equivalent to os.urandom(16)
    )
    cipher, iv = auth.generateCipher(session_key, iv)
    self.init_vector = iv # assign to header
    self.data = auth.encryptBytes(cipher, self.data)
```

The `encryptBytes` method includes the `autoPad` boolean. This ensure thats the `rawBytes` are a suitable length for the `cipher` to encrypt.

```python
def encryptBytes(cipher: Cipher, rawBytes: bytes, autoPad=True) -> bytes:
    if autoPad:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        rawBytes = padder.update(rawBytes) + padder.finalize()
    encryptor = cipher.encryptor()
    encryptedBytes = encryptor.update(rawBytes) + encryptor.finalize()
    return encryptedBytes
```

###### 5.4.2.4.1.2 Decryption

When a `Node` receives a packet with the `ENCRYPT` flag set, it calls `p.decryptData(self.getSessionKey(addr))` (where `p` is the packet). The `decryptData` method first checks that the packet is flagged appropriately (to prevent trying to decrypt an unencrypted packet). It then generates a `cipher` using the packet's init vector and uses this to decrypt the packet data.

```python
def decryptData(self, session_key: bytes) -> None:
    if self.flags[Flag.ENCRYPTED.value]:
        cipher = auth.generateCipher(session_key, self.init_vector)[0]
        self.data = auth.decryptBytes(cipher, self.data)
    else:
        # not flagged for decryption

```

The `decryptBytes` method contains the `autoUnpad` boolean. This is used to automatically remove any padding left by the encryption process.

```python
def decryptBytes(cipher: Cipher, encryptedBytes: bytes, autoUnpad: bool = True) -> bytes:
    decryptor = cipher.decryptor()
    decryptedBytes = decryptor.update(encryptedBytes) + decryptor.finalize()
    if autoUnpad:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decryptedBytes = unpadder.update(decryptedBytes) + unpadder.finalize()
    return decryptedBytes
```

##### 5.4.2.4.2 COMPRESS

The `COMPRESSED` flag allows for the data to be automatically compressed and decompressed when the flag is set.

###### 5.4.2.4.2.1 Compression

When the `Node` goes to queue a packet with the `COMPRESSED` flag set it first calls for the packet to be compressed using the packet's `compressData` method.

```python
def compressData(self) -> None:
    self.flags[Flag.COMPRESSED.value] = 1 # ensure flag set
    self.data = utils.compressData(self.data)
```

The `utils.compressData` method uses the `zlib` library with the default `level`, which compromises speed with efficiency, but the negative of the default `wbits` to enure that no header or checksum is appended to the bytes as this would create unnecessary overhead.

```python
def compressData(data: bytes) -> bytes:
    # default speed
    # no header or checksum
    return zlib.compress(data, -1, -15)
```

###### 5.4.2.4.2.2 Decompression

When a `Node` receives a packet with the `COMPRESS` flag set it first calls for the packet to be decompressed using the packet's `decompressData` method.

```python
def decompressData(self) -> None:
    if self.flags[Flag.COMPRESSED.value]:
        self.data = utils.decompressData(self.data)
    else:
        # not flagged for decompression
```

The `utils.decompressData` method performs the `zlib` decompression using the same `wbits` as the compression to not expect a header or checksum.

```python
def decompressData(data: bytes) -> bytes:
    # no header or checksum
    return zlib.decompress(data, -15)
```

##### 5.4.2.4.3 CHECKSUM

The checksum is defined in the packet specification as a `CRC-32` checksum of a packet's data. The `zlib` library includes a method to generate a `CRC-32` checksum, which this project utilizes.

```python
def generateChecksum(data: bytes) -> int:
    return zlib.crc32(data)
```

###### 5.4.2.4.3.1 Setting a Checksum

When a `Node` goes to queue a packet with the `CHECKSUM` flag set, it first calls for the checksum to be set using the packet's `setChecksum` method.

```python
def setChecksum(self) -> None:
    self.flags[Flag.CHECKSUM.value] = 1 # ensure flag set
    data = self.data if self.data is not None else b"" # sets to empty byte string if None
    self.checksum = utils.generateChecksum(data) # assign to header
```

###### 5.4.2.4.3.2 Validating a Checksum

When a `Node` receives a packet with the `CHECKSUM` flag set, it first checks the packet's data against the checksum using the packet's `validateChecksum` method. The `Node` does not drop the packet on a failure but does raise a warning that the checksum failed.

```python
def validateChecksum(self) -> bool:
    if self.flags[Flag.CHECKSUM.value]:
        data = self.data if self.data is not None else b"" # sets to empty byte string if None
        return self.checksum == utils.generateChecksum(data)
    else:
        # not flagged for checksum validation
```

---

##### 5.4.2.4.4 FRAG

The `FRAG` flag allows for the automatic *fragmentation* of the packet's data into serval sub-packages. These are then resembled into a final *super-packet* once the recipient has collected all the fragments.

###### 5.4.2.4.4.1 Fragmentation

When the `Node` goes to queue a packet with the `FRAG` flag set, the `Node` first calls the packet's `fragment` method. This method splits the packets data into fragmented chunks and creates a list of *fragment* packets.

```python
def fragment(self):
    self.flags[Flag.FRAG.value] = 1 # ensure flag set
    header = Packet._getHeader(self) # returns dictionary of packet's headers (where set)
    fragData = utils.fragmentData(self.data)
    fragment_number = len(fragData)
    return [
        self._createFragment(
            header, fragment_id=i, fragment_number=fragment_number, data=data # set fragment_id, fragment_number and data through comprehension
        )
        for i, data in enumerate(fragData)
    ]
```

The `_createFragment` `classmethod` creates a new class instance with the given attributes.

```python
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
```

The `utils.fragmentData` method splits the data into a list of bytes, splitting the data into fragments with a max size `MAX_FRAGMENT_SIZE`. The `MAX_FRAGMENT_SIZE` is set to $988$ to keep the total packet size under $1024$ (`SOCKET_BUFFER_SIZE`) when including the maximum theoretical header size.

```python
def fragmentData(data: bytes) -> list[bytes]:
    return [
        data[i : i + MAX_FRAGMENT_SIZE] for i in range(0, len(data), MAX_FRAGMENT_SIZE)
    ]
```

###### 5.4.2.4.4.2 Defragmentation

In order to collect all the fragments for reassembly, the `Node` class contains a dictionary `fragBuffer` using the fragments `sequence_id` as the key and a list of the fragments as the values. When a `Node` receives a packet with the `FRAG` flag set it appends it to the `fragBuffer` (creating a new entry if required). It then checks to see if all the `fragBuffer[p.sequence_id]` are set. If so, the fragments can be recompiled into the *super-packet* and passed to `receive` and the buffer entry can be deleted.

```python
def handleFrag(self, p: packet.Packet, addr: tuple[str, int]) -> bool:
    if p.flags[packet.Flag.FRAG.value]:
        if p.sequence_id not in self.getFragBuffer(addr): # new fragment sequence id
            self.getFragBuffer(addr)[p.sequence_id] = [ 
                None for _ in range(p.fragment_number) # Empty list with size == p.fragment_number
            ]
        self.getFragBuffer(addr)[p.sequence_id][p.fragment_id] = p
        if all(self.getFragBuffer(addr)[p.sequence_id]): # all list members not None
            defrag = p.defragment(self.getFragBuffer(addr)[p.sequence_id])
            del self.getFragBuffer(addr)[p.sequence_id] # remove fragment sequence id from dict
            self.receive(defrag, addr)
        return True
    else:
        return False
```

The `defragment` `classmethod` creates a new *super-packet* from a list of fragments.

```python
@classmethod
def defragment(cls, frags):
    if frags[0].flags[Flag.FRAG.value]: # assumes all packets flag state based on the first's
        header = Packet._getHeader(frags[0])
        header["flags"][Flag.FRAG.value] = 0 # de-sets the FRAG flag
        data = utils.defragmentData([frag.data for frag in frags])
        return cls(**header, data=data)
    else:
        # not flagged for defragmentation
```

The `utils.defragmentData` method takes a list of bytes and returns the joined cohesive bytes.

```python
def defragmentData(fragments: list[bytes]) -> bytes:
    return b"".join(fragments)
```

---

##### 5.4.2.4.5 Automatic Handling

The `Node`'s `queuePacket` method is now able to handle all flag variants. The order in which the `Node` performs each flag action is based on the order described by the `Flag`s.

```python
def queuePacket(self, addr: tuple[str, int], p: packet.Packet) -> None:
    # reliable -> checksum -> compress -> encrypt -> frag
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
            self.getQueue(addr).put((addr, frag)) # queue each fragment
    else:
        self.getQueue(addr).put((addr, p)) # queue packet
```

Similarly, the `Node`s `handleFlags` method is now able to handle all flag variants. The order in which the `Node` handles each flag is based on the **reverse** of the order described by the `Flag`s. All the handle methods return a boolean indicating if the flag is present and, thus, the flag action was performed. This is used to return a boolean based on if the packet was a fragment packet. The `receive` method checks the result of `handleFlags` and skips further processing in the event that the flag was a fragment.

```python
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
```

### 5.4.3 Iteration 3

#### 5.4.3.1 ACK Bits and Rolling Reset

The `Node` class utilizes it local record of sent ACKed to set the `ACK Bits`. This helps to mitigate against packet loss as each `ACK` packet also includes an acknowledgment of the last 16 packets (if received). This means when a `Node` revives an `ACK` packet as well as setting the `ACK ID` in its received ACKed packets it also iterates over all the bits in the `ACK Bits` (with their ID set according to the packet specification) and sets accordingly.

```python
def receiveAck(self, p: packet.AckPacket, addr: tuple[str, int]) -> tuple[packet.Packet, tuple[str, int]]:
    self.setNewestSeqId(
        addr, self.getNewerSeqId(self.getNewestSeqId(addr), p.sequence_id)
    )
    self.setSentAckBit(addr, p.ack_id, True)
    # set all bits from ack bits to true (to mitigate lost ack)
    for i, j in enumerate(range(p.ack_id - 1, p.ack_id - 1 - packet.ACK_BITS_SIZE, -1)):
        if p.ack_bits[i]:
            self.setSentAckBit(addr, j, True)
    return (p, addr)
```

The `Node` class also implements a rolling reset on its record of sent ACKs. Without this, the record becomes incorrect after the `sequence id` wrap around at $2^{16}$. To do this the `Node` keeps a record of the *newest* sequence id it has received. To calculate the newer of two ids both ids are subtracted from each other to create two difference values which are both modded with $2^{16}$. The smallest difference gives the newer id.

```python
def getNewerSeqId(currentSeqId: int, newSeqId: int) -> int:
    currentDiff = (newSeqId - currentSeqId) % (2**16)
    newDiff = (currentSeqId - newSeqId) % (2**16)
    if newDiff < currentDiff:
        return currentSeqId
    else:
        return newSeqId
```

Every time a packet is received, it is checked against the newest sequence id and the newest id is updated accordingly. Then, when a `RELIABLE` packet is received, after updating the newest sequence id it calls `resetBits`.

```python
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
```

The `resetBits` method iterates its sent ACKs from the `newest sequence id` to `(newest sequence id + half of array) % 2**16` and resets the bits to `None`. This resets half of all bits after the newest sequence id, accounting for the wrap around, to ensure that there is never confusion from a previously ACKed packet from before a wrap around.

```python
def resetBits(sentACKs: list[bool | None]) -> None:
    ACK_RESET_SIZE = 2**15 # 2**16 / 2
    end = (newestSeqId - ACK_RESET_SIZE) % 2**16
    counter = 0
    while counter != end:
        sentACKs[(newestSeqId + 1 + counter) % 2**16] = None
        counter += 1
```

---

#### 5.4.3.2 HEARTBEAT Packets

When a `Node` receives a packet it updates is `heartbeat` field to be the current datetime (`datetime.datetime.now()`). When a `Server` receives a packet from a client is also updates its heartbeat record for that client.

The `queueHeartbeat` method takes the additional boolean `heartbeat`.

```python
def queueHeartbeat(self, addr: tuple[str, int], heartbeat: bool, flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)], data: bytes | None = None) -> None:
        p = packet.HeartbeatPacket(
            sequence_id=self.getSequenceId(addr),
            flags=flags,
            heartbeat=heartbeat,
            data=data,
        )
        self.incrementSequenceId(addr)
        self.queuePacket(addr, p)
```

The `heartbeatThread` uses the `heartbeat` method.

```python
def startThreads(self) -> None:
        super().startThreads()
        self.heartbeatThread.start()
```

The `Server` checks every `HEARTBEAT_MIN_TIME` (30 seconds) each *connected* client's heartbeat delta (`now() - client.heartbeat`). If the heartbeat delta is greater than some `HEARTBEAT_MAX_TIME` (120 seconds) the client is dropped as it can be assumed to have either terminated or be unresponsive. Otherwise, if the heartbeat delta is greater than `HEARTBEAT_MIN_TIME` the `Server` polls the client by sending a `PING` `HEARTBEAT` packet.

```python
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
```

```python
def removeClient(self, clientAddr: tuple[str, int], debugStr="") -> None:
    if self.checkClientExists(clientAddr):
        cId = self.getClientId(clientAddr)
        with self.clientsLock:
            self.clients[clientAddr].isRunning.clear()
            del self.clients[clientAddr]
            if self.onClientLeave:
                self.onClientLeave(clientAddr, cId)
```

When a `Node` receives a `PING` HEARTBEAT packet is responds with a `PONG` heartbeat.

```python
def receiveHeartbeat(
        self, p: packet.HeartbeatPacket, addr: tuple[str, int]
    ) -> tuple[packet.Packet, tuple[str, int]]:
        if not p.heartbeat:
            self.queueHeartbeat(addr, heartbeat=True)
            pass
        return (p, addr)
```

---

#### 5.4.3.3 Callbacks

The `Node` class can be initiated with an `onReceiveData` callback (taking an addr and some data). This callback is executed whenever a default packet is received, allowing for yielding to an *application* layer.

The `Client` class can additionally be initiated with an `onConnect` callback (taking an addr). The callback is called after a successful handshake is completed, allowing for a game client to begin its `mainloop`.

The `Server` class can additionally be initiated with an `onClientJoin` and `onClientLeave` callback (taking an addr and a ID). These callbacks are called whenever a client is added (i.e. completes a handshake successfully) or removed from the `Server`'s record, allowing for a game server to track its members.

---

#### 5.4.3.4 ERROR Packets

##### 5.4.3.4.1 Exceptions

The python file `udp.error` includes custom `Exceptions` for all errors defined in the Packet Specification as well as `Enum` definitions for the `Major`, and each `Minor`, error code. A base `PaperClipError` class is defined, inheriting `Exception`. Additionally, a base `Minor` enum class is defined to be used as a parent class to the various minors.

```python
class Major(Enum):
    ERROR = 0
    CONNECTION = 1
    DISCONNECT = 2
    PACKET = 3

class Minor(Enum): pass

class PaperClipError(Exception): """Unknown error"""
```

The three `Major` error types then inherent from `PaperClipError`. The relevant `Minor` error code and their `Exceptions` are defined using the `Minor` enum and the `Minor`'s parent `Major` Exception respectively. The method `getConnectionError` takes a `ConnectionErrorCodes` and returns the relevant `ConnectionError`. The method `getConnectionCode` performs the reverse. This pattern is defined for all `Major` and `Minor` Codes and their relevant `Exception`s.

```python
# connection
class ConnectionErrorCodes(Minor):
    CONNECTION = 0
    NO_SPACE = 1
    CERTIFICATE_INVALID = 2
    FINISH_INVALID = 3

class ConnectionError(PaperClipError): """Handshake connection could not be finished"""

class NoSpaceError(ConnectionError): """Server has insufficient space to accept new clients"""

class CertificateInvalidError(ConnectionError): """Certificate is invalid / can not be validated"""

class FinishInvalidError(ConnectionError): """Finish is invalid"""

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
```

Convenience methods allow for conversion between `Enum`s and `PaperClipError`s. The `getError` method takes, either Enum or integer, `Major` and `Minor` codes are returns the relevant `Exception`.

```python
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
```

The `getMinor` method takes a `Major` a int value minor and returns the respective `Minor`.

```python
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
```

The `getErrorCode` method performs the reverse of the `getError` method, taking an `PaperClipError` and returning the relevant `Major` and `Minor` `Enum`.

```python
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

##### 5.4.3.4.2 Sending an ERROR Packet

The `Node`'s `queueError` method takes the additional `Major` and `Minor` fields. The method includes the check `Node`'s `sequenceId` is `None` in which case it uses the value of $0$ instead.

```python
def queueError(
    self, addr: tuple[str, int], major: error.Major | int, minor: error.Minor | int, flags: list[int] = [0 for _ in range(packet.FLAGS_SIZE)], data: bytes | None = None
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
```

`ERROR` packets are automatically queued whenever a `PaperclipError` is generated by surrounding any action that could potentially yield a relent error with `try/except` blocks. This includes all the unpacking of all the fields in the `Packet` with each raising the relevant `PacketError`. Additionally, `ConnectionError`s can arise during the handshake with both the `Client` and `Server` aborting and sending the relevant `ERROR` packet.

```python
def receivePacket(self,) -> tuple[packet.Packet, tuple[str, int]] | tuple[None, None]:
    data, addr = self.socket.recvfrom(SOCKET_BUFFER_SIZE)
    try:
        p = packet.unpack(data) # unpacking can yield a PacketError
        return p, addr
    except error.PacketError as e:
        major, minor = error.getErrorCod(e)
        self.queueError(addr, major, minor)
        return None, None
```

```python
def receive(self, p: packet.Packet, addr: tuple[str, int]) -> tuple[packet.Packet, tuple[str, int]] | None:
    if p is not None:
        if self.handleFlags(p, addr):
            match p.packet_type:
                # packet type cases omitted for clarity
                case _: # unknown packet type
                    self.queueError(
                        addr,
                        major=error.Major.PACKET,
                        minor=error.PacketErrorCodes.PACKET_TYPE,
                        data=p.sequence_id,
                    )
```

##### 5.4.3.4.3 Receiving an ERROR Packet

When receiving an `ERROR` packet, the `receive` method passes the packet to the `receiveError` method within a `try/except` block. The `receiveError` method derives and raises the relevant `PaperclipError` from the packet's `Major` and `Minor` fields. The data field is used to append additional information to the derived `Exception`. This causes the `try/except` block to pass the error to `handleError` which, in turn, passes the error to the relevant error handler.

```python
case packet.Type.ERROR:
    try:
        return self.receiveError(p, addr)
    except error.PaperClipError as e:
        self.handleError(p, addr, e)
```

```python
def receiveError(self, p: packet.ErrorPacket, addr: tuple[str, int]) -> None:
        raise error.getError(p.major, p.minor)(p.data)
```

```python
def handleError(self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.PaperClipError) -> None:
    match e:
        case error.ConnectionError():
            self.handleConnectionError(p, addr, e)
        case error.DisconnectError():
            self.handleDisconnectError(p, addr, e)
        case error.PacketError():
            self.handlePacketError(p, addr, e)
        case _:
            raise e
```

If a `Node` receives a `ConnectionError` the `Node` abort's the connection and calls the `quit` method to gracefully stop threads.

```python
    def handleConnectionError(self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.ConnectionError) -> None:
        match e:
            case error.NoSpaceError():
                return self.quit("no server space", e)
            case error.CertificateInvalidError():
                return self.quit("invalid certificate", e)
            case error.FinishInvalidError():
                return self.quit("invalid finish", e)
            case _:
                raise e
```

The `handleDisconnectError` provides a method to be overridden by the `Client` and `Server`.

```python
    def handleDisconnectError(
        self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.DisconnectError) -> None:
        match e:
            case error.ServerDisconnectError:
                pass  # overwrite
            case error.ClientDisconnectError:
                pass  # overwrite
            case _:
                raise e
```

If a `Node` receives a `PacketError` it performs no additional actions.

```python
    def handlePacketError(self, p: packet.ErrorPacket, addr: tuple[str, int], e: error.PacketError) -> None:
        pass
```

---

#### 5.4.3.5 Disconnects

The `Node` provides an overridable convenience method for sending a `DisconnectError`. Both the `Client` and `Server` override this method to replace the minor with `error.DisconnectErrorCodes.CLIENT_DISCONNECT` and `error.DisconnectErrorCodes.SERVER_DISCONNECT` respectively.

```python
def queueDisconnect(self, addr: tuple[str, int], flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)], data: bytes | None = None) -> None:
    self.queueError(
        addr,
        flags=flags,
        major=error.Major.DISCONNECT,
        minor=error.DisconnectErrorCodes.DISCONNECT,
        data=data,
    )
```

##### 5.4.3.5.1 Client Disconnect

The `Client` overrides the `handleDisconnectError` method to call `_quit` on a `ServerDisconnectError`. The methods `quit` and `_quit` perform the same actions of gracefully stopping the threads but `quit` also includes sending a `ClientDisconnectError` to the server **before** terminating. As the `Server` has initiated the termination, `_quit` is called to skip sending the error.

```python
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
```

##### 5.4.3.5.2 Server Disconnect

The `Client` overrides the `handleDisconnectError` method to call `removeClient` to close the client instance `Node`. Unlike the `Client`, the `Server` does not terminate.

```python
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

The `Server` also overrides the `queueDisconnect` to send a `ServerDisconnectError` to **all** clients. This is called on a `Server` `quit` (along with the termination of threads).

```python
def queueDisconnect(self, flags: list[bool] = [0 for _ in range(packet.FLAGS_SIZE)], data: bytes | None = None):
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
```

### 5.4.4 Iteration 4

#### 5.4.4.1 DotEnv

Variables previously defined as `CONST`s are moved into a central `.env` file. This allows for easier value management.

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

The variables can then be loaded from the `os.environ` by first calling `dotenv.load_dot(".env")`. This is done each each package's `__init__` file.

The `udp.__init__` loads all the relevant variables for the `udp` package to constants, which can then in turn be imported in each script using `from . import VAR_NAME_ONE, VAR_NAME_TWO, VAR_NAME_N` (where `VAR_NAME` is the name of the `CONST` to be imported)

```python
import os
import dotenv

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
```

---

#### 5.4.4.2 Logging

A `logging.Logger` is used to provided runtime logging of system outputs. The logging module provides the option of logging with different levels (e.g. `DEBUG`, `INFO`, `ERROR`) allowing different situations to provide different outputs. A logger is initiated in the `udp.__init__` with a default log level of `DEBUG`. Additionally, `bcolors` includes a various `ASCII` color codes to allow for rich-color output to the console.

```python
import logging
import sys

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

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
```

A `StreamHandler` `printHandler` is defined to output to `sys.stdout` with the default level of `INFO` allowing all messages with `INFO` or higher (i.e. not `DEBUG`) to be printed to the console. `printHandler` is given a `logging.Formatter` so that the `threadName` (colored blue) is recorded with the inputted message.

```python
printHandler = logging.StreamHandler(sys.stdout)
printHandler.setLevel(logging.INFO)
printHandler.setFormatter(
    logging.Formatter(f"{bcolors.OKBLUE}%(threadName)s{bcolors.ENDC} - %(message)s")
)
logger.addHandler(printHandler)
```

A `FileHandler` `fileHandler` is defined to output to `paperclip.log` with the default level `DEBUG` meaning all messages are recorded. `fileHandler` is given a `Formatter` such that each message contains the `asctime`, `levelname` and `threadName` in addition to the inputted message. Additionally, a custom `logging.Filter` `ColorFilter` is defined to remove any ASCII color codes from messages allowing for log messages to include color codes for **only** the console output.

```python
class ColorFilter(logging.Filter):
    colorCodes = [
        getattr(bcolors, attr) for attr in dir(bcolors) if not attr.startswith("__")
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        for color in self.colorCodes:
            record.msg = record.msg.replace(color, "")
        return True

fileHandler = logging.FileHandler("paperclip.log")
fileHandler.setLevel(logging.DEBUG)
fileHandler.addFilter(ColorFilter())
fileHandler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
)
logger.addHandler(fileHandler)
```

The `logger.info` method is used to record typical behaviors.

```python
logger.info(f"{bcolors.OKBLUE}> {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}") # INFO: log outgoing packet
logger.info(f"{bcolors.OKBLUE}< {addr} :{bcolors.ENDC} {bcolors.OKCYAN}{p}{bcolors.ENDC}") # INFO: log incoming packet
```

The `logger.warning` method is used to record whenever something has not occurred as expected (without causing an error)

```python
logger.warning(f"\tInvalid checksum: {p}") # WARNING: log invalid checksum
```

The `logger.error` method is used to record whenever an error occurs.

```python
logger.error(f"{bcolors.FAIL}# > {bcolors.ENDC}{bcolors.OKBLUE}{addr} :{bcolors.ENDC} {bcolors.FAIL}{type(e).__name__}:{e.args[0] if len(e.args) > 0 else ''}{p}{bcolors.ENDC}") # WARNING: log a PaperclipError
```

The `logger.critical` method is used to record whenever a **critical** error occurs meaning the program is unable to continue running.

```python
logger.critical(f"Invalid peer cert {p.certificate}") # CRITICAL: log invalid (server) certificate yielding an abort
```

![example of server console output](media\server-demo-out.jpg)

---

#### 5.4.4.3 Database Models

The database models are implemented as `SQLAlchemy` `db.models`.

```python
uri = os.environ.get("SQLALCHEMY_DATABASE_URI") # get uri from .env
_init = False
if not database_exists(uri): # create database if not exists
    _init = True
    create_database(uri)
app.config["SQLALCHEMY_DATABASE_URI"] = uri

db.init_app(app)

with app.app_context():
    db.create_all() # create all tables
    
if _init: # if database was created
    with app.app_context(): # create some dummy data
        # init games
        from rps import ID, NAME, MIN_PLAYERS, MAX_PLAYERS
        Statement.createGame(ID, NAME, MIN_PLAYERS, MAX_PLAYERS)  
        # example accounts
        m = Statement.createAccount("Mario", "ItsAMe123")
        p = Statement.createAccount("Peach", "MammaMia!")
        b = Statement.createAccount("Bowser", "M4r10SucK5")
        Statement.createFriends(m.id, p.id)
        Statement.createFriends(p.id, b.id)
```

The models were largely implemented according to the `ERD` with some additional fields. The `Statement` class contains various convenience methods for acting on the database (i.e. getting, creating and deleting rows).

##### 5.4.4.3.1 Friends Model

The `Friends` class is implemented according to the `ERD`.

```python
class Friends(db.Model):
    account_one_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )
    account_two_id = db.Column(
        db.Integer, db.ForeignKey("account.id"), primary_key=True
    )
```

The `Statement` for creating friends ensures that `idOne < idTwo`. This allows for easier look-ups of the data as the oder of the given accountIds can be derived.

```python
class Statement:
    @staticmethod
    def getFriends(accountId: int) -> list[Account]: # retrieve list of Accounts who are Friends with id
        friends = Friends.query.filter( # filter where either account_one_id or account_two_id is accountId 
            (Friends.account_one_id == accountId)
            | (Friends.account_two_id == accountId)
        )
        friends = [ # get the account_id of the other account
            friend.account_one_id
            if friend.account_one_id != accountId
            else friend.account_two_id
            for friend in friends
        ]
        friends = [Statement.getAccount(id) for id in friends] # get list of accounts
        return friends

    @staticmethod
    def createFriends(accountIdOne: int, accountIdTwo: int) -> Friends: # create, commit and return Friends
        # enure that idOne < idTwo for index efficiency & easier look-up
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends(account_one_id=idOne, account_two_id=idTwo)
        db.session.add(friends)
        db.session.commit()
        return friends

    @staticmethod
    def removeFriends(accountIdOne: int, accountIdTwo: int) -> bool: # delete Friends. True on success.
        # ensure that idOne < idTwo
        idOne = min(accountIdOne, accountIdTwo)
        idTwo = max(accountIdOne, accountIdTwo)
        friends = Friends.query.filter(
            (Friends.account_one_id == idOne) & (Friends.account_two_id == idTwo)
        )
        if friends is not None: 
            friends.delete() # delete
            db.session.commit()
            return True
        else:
            return False
```

##### 5.4.4.3.2 Game Model

The `Game` model was expanded to also include a string `Name`, for better usability, as well as integer `min_players` and `max_players` fields so a game server is able to start the game after enough members have joined as well as prevent too many players from joining respectively. The `max_players` is also used so the `API` `Server` (via the `LobbyHandler`) can tell which `Lobbies` are full.

```python
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    min_players = db.Column(db.Integer, default=1)
    max_players = db.Column(db.Integer)
```

`Statements` are defined to allow for the creation and retrieval of `Game`s. The `getGames` method allows for all games to be retrieved.

```python
class Statement:
    @staticmethod
    def getGame(gameId: int) -> Game:
        return Game.query.filter_by(id=gameId).scalar() # retrieve Game by id

    @staticmethod
    def getGames() -> list[Game]:
        return Game.query.all() # retrieve all Game

    @staticmethod
    def createGame(id:int, name:str, min_players:int, max_players:int) -> Game: # create, commit and return Game
        game = Game(id=id, name=name, min_players=min_players, max_players=max_players)
        db.session.add(game)
        db.session.commit()
        return game

    @staticmethod
    def findGame(gameName: str) -> Game | None:
        return Game.query.filter_by(name=gameName).scalar() # retrieve Game by name
```

##### 5.4.4.3.3 Account Model

The `Account` model was expanded to also include `private_key` and `public_key` which are `DER` bytes formatted versions of each account's `RSA` key. `SQLAlchemy` also allows for models to contain additional methods for use with instance variables. This allowed for security features such as the hashing of passwords and generation of `RSA` key to be performed on a new instance before it is committed to the database.

```python
class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(162), nullable=False)
    private_key = db.Column(db.LargeBinary(1337)) # DER bytes private RSA key
    public_key = db.Column(db.LargeBinary(294)) # DER bytes public RSA key

    def hashPassword(self, password: str) -> None:
        self.password = generate_password_hash(password)

    def verifyPassword(self, password: str) -> bool:
        return check_password_hash(self.password, password)

    def generateKey(self, password: bytes) -> None:
        k = auth.generateRsaKey()
        self.private_key = auth.getDerFromRsaPrivate(k, password) # encrypts DER with password for security
        self.public_key = auth.getDerFromRsaPublic(k.public_key())

    @staticmethod
    def decryptKey(self, key: bytes, password: bytes) -> auth.rsa.RSAPublicKey:
        k = auth.getRsaPrivateFromDer(key, password)
        return k
```

`Statements` are defined to allow for the creation and retrieval of `Account`s. The `createAccount` method ensures that the password is hashed as well as generating a RSA key for the `Account` before the it is committed.

```python
class Statement:
    # get
    @staticmethod
    def getAccount(userId: int) -> Account:
        return Account.query.filter_by(id=userId).scalar() # retrieve Account by id

    # create
    @staticmethod
    def createAccount(username: str, password: str) -> Account: # create, commit and return Account
        account = Account(username=username)
        account.hashPassword(password) # hash password
        account.generateKey(password.encode()) # generate RSA key
        db.session.add(account)
        db.session.commit()
        return account

    # find
    @staticmethod
    def findAccount(username: str) -> Account | None:
        return Account.query.filter_by(username=username).scalar() # retrieve Account by username
```

##### 5.4.4.3.4 Lobby Model

Finally, upon reflection, the `Lobby` and `LobbyMembers` models and their behaviour were better suited as python class instances (i.e. were removed from the database). The `Lobby` model was refactored into a `Lobby` class which is responsible for initiating and running a game server instance. In addition to this, the `Lobby` class is responsible for tracking and reporting lobby members, so no `LobbyMembers` class is needed.

```python
def isNotFull(self) -> bool:
    return self.gameServer.isNotFull()

def isEmpty(self) -> bool:
    return len(self.members) == 0
```

A `LobbyHandler` class was created to manage the creation of `Lobby`s and the `API` `Server` uses this when dispatching new `Lobby`s rather than creating them directly. The `LobbyHandler` is also responsible for *pruning* lobbies. In a `pruneThread` the `LobbyHandler` iterates over all of the `Lobby` instances and checks their heartbeat (in a similar fashion to how a `udp.Server` removes old clients). The `prune` method creates a copy of `lobbies` list to iterate over (rather than iterating over the `lobbies` themselves). It can be assumed that any `Lobbies` created during the execution of the prune loop will not be old enough to be pruned.  If a `Lobby` has contained no members for some `PRUNE_TIME` (60 seconds) the `LobbyHandler` stops and removes it to free up resources.

```python
def prune(self) -> None:
        while self.isRunning:
            with self.lobbiesLock:
                lobbies = self.lobbies.copy() # create copy to iterate over for better thread-safety.
            for lobby in lobbies:
                if lobby.isPrune():
                    logger.info(
                        f"{bcolors.FAIL}# Lobby {lobby} was removed due to PRUNE (delta={lobby._heartbeatDelta()}){bcolors.ENDC}"
                    )
                    self.deleteLobby(lobby.addr)
            time.sleep(PRUNE_TIME)
```

The `Lobby` contains the `isPrune` method allowing the `LobbyHandler` to determine if the `Lobby` should be deleted.

```python
def isPrune(self) -> bool:
    if isinstance(self.heartbeat, datetime.datetime):
        delta = self._heartbeatDelta()
        if delta > PRUNE_TIME:  # check if server has been empty for > PRUNE_TIME
            return True
    return False

def _heartbeatDelta(self) -> int:
        return (datetime.datetime.now() - self.heartbeat).seconds
```

When a client joins the `Lobby` it sets the heartbeat to `true` to indicate it has active members. When a client leaves the `Lobby`, if the `Lobby`'s has no members, it sets the heartbeat to `now()`.

```python
def onJoin(self, addr: tuple[str, int], accountId: int) -> None:
    self.members.append(accountId)
    self.heartbeat = True

def onLeave(self, addr: tuple[str, int], accountId: int) -> None:
    self.members.remove(accountId)
    if self.isEmpty():
        self.heartbeat = datetime.datetime.now()
```

---

#### 5.4.4.4 RESTful Server

The `RESTful` `Server` was implemented using as a `Flask` app.

##### 5.4.4.4.1 API Authentication

`HTTPBasicAuth` allows for easy authentication with a username and password and can restrict access to certain endpoints unless authentication is provided (using the `@auth.login_required` decorator). `JSON Web Tokens` (`JWT`) are used for session tokens, allowing a user to instead request and use a token for the rest of the session (or until the token expires) instead of using a username and password. This can help mitigate against any man-in-the-middle attacks as, if a token is successfully intercepted, it will only be useable for a limited time and the accounts credentials are not exposed.

The `verifyPassword` method used by `auth` first checks if it has been given a token. Otherwise, the method attempts to validate with the username and password.

```python
auth = HTTPBasicAuth()

@auth.verify_password
def verifyPassword(username: str, password: str) -> bool:
    account = Statement.validateToken(username)  # check token
    if not account:  # if token not valid
        account = Statement.findAccount(username=username)  # check account
        if not account or not account.verifyPassword(
            password
        ):  # if account not exist or wrong password
            return False
    g.account = account # store (until overwrite) in flask globals
    return True
```

`JWT` tokens are generated using the `Account` class's `generateToken` method. The tokens include the `Account.id` and remain valid for `expiration` seconds (default to 600).

```python
def generateToken(self, expiration: int = 600) -> str:
        data = {
            "id": self.id,
            "exp": datetime.datetime.now() + datetime.timedelta(seconds=expiration), 
        }
        token = jwt.encode(data, current_app.config["SECRET_KEY"], algorithm="HS256")
        return token
```

Tokens are validated using `Statement.validateToken` which calls the `Account.validateToken` static method.

```python
class Statement:
    @staticmethod
    def validateToken(token: str) -> Account | None:
        return Account.validateToken(token)
```

The `Account.validateToken` method performs the `JWT` decode function on the token. This includes checks for token expiry. On a success it returns the `Account` with the relevant `id`.

```python
@staticmethod
def validateToken(token: str):
    try:
        data = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            leeway=datetime.timedelta(seconds=10),
            algorithms=["HS256"],
        )
    except:
        return None
    account = Statement.getAccount(data.get("id"))
    return account
```

##### 5.4.4.4.2 Endpoints

The endpoints are implemented according to the `API` specification.

###### 5.4.4.4.2.1 Auth

The `createAccount` method is exposed at `/auth/register` and accepts **only** `POST` requests. The method takes a username and password field from the request's `JSON` and creates a new account. The `Account.id` and `Account.username` are returned with the `HTTP` code $201$ to indicate successful account creation.

```python
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
```

The `getAuthToken` method is exposed at `/auth/token` and accepts **only** `GET` requests. The method generates and returns a token derived from the logged-in `Account`.

```python
@main.route("/auth/token")
@auth.login_required
def getAuthToken():
    return jsonify({"token": g.account.generateToken()})
```

The `getKey` method is exposed at `/auth/key` and accepts **only** `GET` requests. The method retrieves the `DER` `private_key` associated with the logged-in `Account`. The key is `base64` encoded as a sanitation step to ensure it can be encoded in `URL` safe `JSON`.

```python
@main.route("/auth/key")
@auth.login_required
def getKey():
    return jsonify(
        {
            "key": base64.encodebytes(g.account.private_key).decode(),
            "account-id": g.account.id,
        }
    )
```

###### 5.4.4.4.2.2 Friends

The `getFriends` method is exposed at `/friends` and accepts **only** `GET` requests. The method returns a list of dictionaries of all `Account.id` and `Account.username` where the `Account` is friends with the logged-in account.

```python
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
```

The `addFriend` method is exposed at `/friends/add` and accepts **only** `POST` request. The method derives two accounts, one from the logged-in account and the other from the username field in the request's `JSON`. The method then creates a new `Friends` entry and returns the `Account.id` and `Account.username` of both `Account`s along with the `HTTP` code $201$.

```python
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
```

The `removeFriend` method is exposed at `/friend/remove` and accepts **only** `DELETE` requests. The method derives two accounts, in the same way as `addFriend` and deletes the `Friends` from the database. The method returns $204$ to indicate a successful deletion

```python
@main.route("/friend/remove", methods=["DELETE"])
@auth.login_required
def removeFriend():
    username = request.json.get("username")
    if username is None:
        abort(400)  # missing args
    account = g.account
    other = Statement.findAccount(username)
    if other is None:
        abort(404) # no such account
    success = Statement.removeFriends(account.id, other.id)
    if success:
        return jsonify(data=[]), 204
    else:
        abort(404) # no such friends
```

###### 5.4.4.4.2.3 Games

The `getGames` method is exposed at `/games` and accepts **only** `GET` request. The method returns a list of all available games.

```python
@main.route("/games/")
@auth.login_required
def getGames():
    return jsonify({game.id: game.name for game in Statement.getGames()})
```

###### 5.4.4.4.2.4 Lobby

The `getLobby` method is exposed at `/lobby` and acceptes **only** `GET` requests. The method derives a `Lobby` from the `LobbyHandler`, using the the `lobby-id` in the request's `JSON`, and returns the `Lobby`'s `id`, `addr` and `gameId`.

```python
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
```

The `getLobbies` method at `/lobby/all` complies all lobbies currently in the `LobbyHandler`. It the returns a variety of information on each lobby in a list of dictionaries. The information includes the `lobby-id`, the `game` (with `game-id` and `game-name`) associated with the `Lobby`, the max `size` and if the lobby `is-full`.

```python
@main.route("/lobby/all")
@auth.login_required
def getLobbies():
    lobbies = LobbyHandler.getAll()
    games = {game.id: game.name for game in Statement.getGames()}
    data = lambda lobby: { 
        "game": {"game-id": lobby.game_id, "game-name": games[lobby.game_id]},
        "size": Statement.getLobbySize(lobby.id),
        "is-full": Statement.getIsLobbyFree(lobby.id),
    }
    return jsonify({lobby.id: data(lobby) for lobby in lobbies})
```

The `findLobby` method at `/lobby/find` finds a `Lobby` instance with available space (i.e. `isNotFull`) using either the `gameId` or `gameName` provided in the request's `JSON`. The method returns the `lobby-id`, `lobby-addr` and `game-id` in a dictionary.

```python
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
```

The `createLobby` method is exposed at `/lobby/create` and accepts **only** `POST` requests. The method creates a new `Lobby` instance using the `LobbyHandler` and the game.id derived from either the `game-id` or `game-name` included in the request's `JSON`.

```python
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
```

The `getMembers` method at `/lobby/members/` returns a dictionary of all members of all lobbies.

```python
@main.route("/lobby/members")
@auth.login_required
def getMembers():
    return jsonify(lobbyHandler.getMembers())

# LobbyHandler.getMembers
def getMembers(self) -> dict[int, list[int]]:
        with self.lobbiesLock:
            return {lobby.id: lobby.members for lobby in self.lobbies}
```

The `getFriendLobbies` method at `/lobby/friends` returns all `Lobby`s which contain an `Account` which is `Friends` with the logged-in `Account` as long as the `Lobby` has space. It calls `lobbyHandler.getMember` to retrieve the relevant `Lobby`s.

```python
@main.route("/lobby/friends")
@auth.login_required
def getFriendLobbies():
    friends = Statement.getFriends(g.account.id)
    lobbyInfo = lambda lobby: {
        "lobby-id": lobby.id,
        "game-id": lobby.gameId,
        "game-name": Statement.getGame(lobby.gameId).name,
    }
    accountInfo = lambda account: {
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

The `LobbyHandler.getMember` method returns a list of all `Lobby`s an containing an `Account` with `Account.id == accountId`. It performs an additional check to only return `Lobby`s with available space (i.e. `isNotFull()`).

```python
def getMember(self, accountId: int) -> list[Lobby]:
    with self.lobbiesLock:
        return [
            lobby
            for lobby in self.lobbies
            if lobby.isNotFull() and accountId in lobby.getMembers()
        ]
```

---

#### 5.4.4.5 Certificates and Handshake Update

The `validateCert` method is exposed at `auth/certificate/validate` and accepts **only** `GET` requests. The method a `DER` certificate from the request's `JSON` and (after `base64` decoding) converted to a `x509.Certificate` instance. The `Account` can then be derived using the `account-id` from the certificate attributes and the associated `DER` `Account.public_key` can be retried and converted to an `rsa.RSAPublicKey` instance. If an `account-id` is not present the certificate is checked against the `Server`'s `RSA` key. The validity can then be checked and returned along with the derived `Account.id`.

```python
@main.route("/auth/certificate/validate")
def validateCert():
    valid = False
    certificate = request.json.get("certificate")
    certificate = base64.decodebytes(certificate.encode()) # base64 decode
    if certificate is not None:
        certificate = udp.auth.getCertificateFromDer(certificate) # get x509.Certificate instance
        attributes = udp.auth.getUserCertificateAttributes(certificate)
        if attributes["account-id"] is not None:
            account = Statement.getAccount(attributes["account-id"]) # get Account instance
            publicKey = udp.auth.getRsaPublicFromDer(account.public_key) # get rsa.RSAPublicKey instance
        else:
            publicKey = rsaKey.public_key()
        valid = udp.auth.validateCertificate(certificate, publicKey)
        return jsonify({"valid": valid, "account-id": attributes["account-id"]})
    else:
        abort(400)  # missing args
```

The `udp.auth.validateCertificate` method takes a `x509.Certificate` and `rsa.RSAPublicKey` instance. The method first checks that the certificate period. If the certificate has not expired the `publicKey` can then be used to verity the `certificate`. If a `InvalidSignature Exception` does not arises the method returns `True`. Otherwise, if either the period or verify checks fail, the method returns `False`.

```python
def validateCertificate(certificate: x509.Certificate, publicKey: rsa.RSAPublicKey) -> bool:
    # period
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc): # check in period
        return False
    # signature
    try:
        publicKey.verify( # check against publicKey
            certificate.signature,
            certificate.tbs_certificate_bytes,
            aPadding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False
    return True
```

The `udp.auth.generateUserCertificate` method is updated to allow for an `Account.id` `userId` and `Account.username` `username` to be passed for embedding into the `x509.NameAttribute`s.

```python
def generateUserCertificate(key, userId: int | str | None = None, username: str | None = None) -> x509.Certificate:
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
            ### omitted for clarity
    )
    return cert
```

The `udp.Client.validateCertificate` method can now be defined using a `requests.get` to retrieve validation from the `RESTful` server.

```python
def validateCertificate(self, certificate: auth.x509.Certificate) -> bool:
        url = f"http://{self.targetHost}:5000/auth/certificate/validate"
        headers = {"Content-Type": "application/json"}
        certificate = base64.encodebytes(
            auth.getDerFromCertificate(certificate)
        ).decode()
        data = {"certificate": certificate}
        try:
            r = requests.get(url, headers=headers, data=json.dumps(data))
            if r.status_code == 200:
                return r.json()["valid"]
            else:
                return False
        except:
            # server unresponsive
            return False
```

The `udp.Server.validateCertificate` is implemented as the same except for returning the `account-id` instead of the boolean `True`.

```python
def validateCertificate(self, certificate: auth.x509.Certificate) -> bool|int:
    # omitted for clarity
        if r.status_code == 200:
            return r.json()["valid"], r.json()["account-id"]
        else:
            return False
    # omitted for clarity
```

---

#### 5.4.4.6 RPS Demo

The Rock, Paper, Scissors (`rps`) python package contains a game `rps.Server` and `rps.Client` using `udp.Server` and `udp.Client` respectively.

The choice and outcomes are defined in the package `__init__` allowing both the `Client` and `Server` to import them.

```python
class Choice:
    ROCK = 0
    PAPER = 1
    SCISSORS = 2


class Outcome:
    LOOSE = 0
    WIN = 1
    DRAW = 2
```

The `Game` attributes are defined in `game_config.yaml`.

```yaml
NAME: "RPS"
ID: 1
MIN_PLAYERS: 2
MAX_PLAYERS: 2
```

These can then be loaded using the `yaml` package in the `__init__`.

```python
# config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "game_config.yaml")

with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

ID = config["ID"]
NAME = config["NAME"]
MIN_PLAYERS = config["MIN_PLAYERS"]
MAX_PLAYERS = config["MAX_PLAYERS"]
```

##### 5.4.4.6.1 Client

The `Client` contains a simple command line UI which guides the user through playing RPS. Once a user has inputted its choice it sends the choice (with the `RELIABLE` flag set) to the `Server` and waits for a reply. Upon receiving the outcome and scores, it displays the output to the user and waits for a new choice to be selected.

The `Client` uses the `onReceiveData` callback to receive data into the `receive` method where the data is added to a `queue.Queue` `recvQueue` after being decoded. All data is sent as `RELIABLE` default packets containing a `JSON` encoded payload.

```python
def send(self, addr: tuple[str, int], data: json) -> None:
    self.udpClient.queueDefault(
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
```

The `gameloop` method takes a user input `choice` and sends it to the `Server`. It then waits for the `recvQueue` to contain a reply and then updates the score and displays the results to the user. The `gameThread` is defined as `self.gameThread = Thread(name=f"{addr[1]}:Gameloop", target=self.gameloop, daemon=True)` allowing the `gameloop` to execute in its own thread.

```python
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
```

The `Client` utilizes the `onConnect` to start the `gameThread`.

```python
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
```

##### 5.4.4.6.2 Server

The `Server` waits for two `Client`s to join and send their choices. The server then calculates the outcome (i.e. `WIN`, `LOSE`, `DRAW`) and sends this to both `Client`s along with their new scores.

The `Server` contains two static methods `evaluateWin` and `evaluatePlayerChoices` which are used to calculate the winner to two choices.

```python
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
```

The `onClientJoin` and `onClientLeave` callbacks are utilized to manage the `Server`'s player record `players`. `players` takes the form `dict[tuple[str, int], dict[str, int]]` where `Client` addresses are used as a key and the values contain a dictatory of player `accountId`s and `score`s. These values are retrieved and set through getters and setter which make use of a `thread.Lock` to ensure thread-safety.

```python
def playerJoin(self, addr: tuple[str, int], accountId: int) -> None:
    with self.playersLock:
        self.players[addr] = {"score": 0, "accountId": accountId}
    if self.onClientJoin:
        self.onClientJoin(addr, accountId)

def playerLeave(self, addr: tuple[str, int], accountId: int) -> None:
    with self.playersLock:
        del self.players[addr]
    if self.onClientLeave:
        self.onClientLeave(addr, accountId)
```

The `Server` `mainloop` method waits for `MAX_PLAYERS` to join. Once enough players have join, the method calls `getChoices` and computes the `outcomes`. The `outcomes` are then restructured for each client into a payload and the scores are updated and included in the payload. The relevant payload is then dispatched to each client. The loop then checks that it is both running and the `Server` has the appropriate number of players. If so the loop repeats.

```python
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
```

The `getChoices` method waits for inputs from all players before returning their choices.

```python
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
```

---

#### 5.4.4.7 Client

The `Client` python package contains a simple command line UI that handles communication (including providing the reliant authentication) to the RESTful server using the `requests` package. Once a user creates a new or joins a `Lobby` the `Client` creates the relevant game client and connects to the game server. If a user exits a game, it is returned to the `Client` command line UI.

##### 5.4.4.7.1 Authentication

On `Client` initialization the `Client` uses the provided username and password to retrieve the session token.

```python
@staticmethod
def getToken(username: str, password: str) -> str:
    url = SERVER_URL + "/auth/token"
    r = requests.get(url, auth=(username, password))
    assert r.status_code == 200, r
    return r.json()["token"]
```

The `Client` then uses `requests.auth.HTTPBasicAuth` for the rest of the session communications.

```python
class Client:
    def __init__(self, username: str, password: str, token: str | None = None) -> None:
        self.username = username
        self.password = password
        self.gameClient = None
        self.token = (
            token if token is not None else self.getToken(self.username, self.password)
        )
        self.auth = HTTPBasicAuth(self.token, "")
        self.getKey(password.encode())
```

The `Client` maps all of the `RESTful` endpoints to methods containing the relevant endpoint and request (with auth).

##### 5.4.4.7.2 UI

The user is initially greeted with the options to either log-in or create an account.

![example output of client with logging and friends](media\client-demo-friends.jpg)

The user is guided through various text menus allowing them to perform various task including:

- viewing and managing account `Friends`

- view all `Game`s

- create or join a `Lobby`

![example output of client with matchmaking and game client creation](media\client-demo-match.jpg)

##### 5.4.4.7.3 Matchmaking

The `Lobbies` menu includes the option for matchmaking. The `_matchmaking` method first attempts to find an available `Lobby`. If this fails, the method creates a new `Lobby`. The relevant game `Client` is then created and connected to the game `Server`.

```python
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
```

The `join` method handles creating the relevant game `Client` and joining the `Lobby` using the provided `lobbyId`.

```python
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
```

## 5.5 Tests

The `pytest` module was used to define serval test.

![example output of `pytest -v`](media\pytests.jpg)
