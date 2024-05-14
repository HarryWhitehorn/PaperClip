# 3 Literature Review

## 3.1 Network Protocols

When considering the transport layer the two primary options for sending data are `TCP` [@rfc9293] and `UDP` [@rfc768]. Both have their own strengths and weaknesses.

### 3.1.1 TCP

`TCP` is a protocol that uses a connection-based approach. It offers a reliable, ordered and error-checked data stream. It is used for a variety of other protocols such as `HTTP`, `FTP` and `SMTP`. These features, while offering benefits also come with drawbacks such as additional overhead which in part contributes to `TCP` prioritizing data integrity at the expense of latency.

- Reliable
    - The sender is notified if a packet is successfully, or unsuccessfully, delivered to its recipient. This means the data is re-sent in the event of packet loss, ensuring that all data is received (unless of a major failure such as the recipient losing connection e.g. though power loss). This, however, incurs a larger overhead than unreliable protocols leading to typically slower data transfer.

- Ordered
    - Packets are received by their destination in the same order they are sent. This is achieved by assigning a sequence number to each segment of data. The receiver is then able to reassemble the data in the correct order. This, however, can lead to increased latency when a recipient is waiting for a packet after receiving its descendant causing the data stream to hang.

- Error-checked
    - A checksum is included with the packet data. This allows for a recipient to verify that the data is received in the same state it was sent. In the event of data corruption, the data is re-requested. This also contributes to increased latency as the recipient must wait for the packet to be retransmitted.

---

### 3.1.2 UDP

In contrast, `UDP` is a connectionless protocol that is unreliable, unordered and provides no error-correction at the interface level (i.e. error-correction must be implemented on the application layer if desired). Despite these simplicities, `UDP` is arguably more suited to fast, real-time communication where speed is prioritized over integrity.

- Connectionless
    - Due to `UDP` being a connectionless protocol, `UDP` is able to broadcast and multicast packets without any additional overhead. This, for example, is useful when a server has to send a game-state update to all game clients.

- Unreliable
    - There are no systems in place to detect if a packet is successfully delivered. This, therefore, means that there is a significant reduction in latency as no resubmission takes place but also means that packets can be lost without either the sender or the recipient being aware.

- Unordered
    - Packets may arrive in any order and it is up to the application to determine the original order. There is no built-in information in the packet to infer the original order either and thus, if this information is desired, must be encoded into the packet payload. This, however, gives the recipient more flexibly, allowing outdated packets to simply be ignored in the event that a newer packet has already been processed.

- No error-checking
    - Though the `UDP` contains a checksum field, this is not mandatory (at least for `IPv4`). In the event the checksum is used, any packets that fail the checksum will be dropped at the transport layer and will not reach the application. Due to this, it can be beneficial to not include a checksum in the header and instead implement some form of data validation in the data payload instead.

---

### 3.1.3 Comparison

When working with time critical data such as that required for real-time video games, particularly those with fast-paced interactions, like FPS such as *Quake* [@quake] or fighting games such as *Street Fighter IV* [@streetfighter4] `TCP`'s overhead leads to a too great latency. Many systems would also prefer to just discard packets in the event of a failure as waiting for retransmission will yield old and outdated information no longer relevant to the current state of the system. These such use-cases are ideal for `UDP`, though some additional features may have to be implemented on the application level (some borrowed from `TCP`). The consensus among game developers is typically to implement a custom protocol based on `UDP`.

> "Using TCP is the worst possible mistake you can make when developing a multiplayer game."
*UDP vs. TCP* [@fiedle-2008]

Several implementations attempt to add key features to the `UDP` specification such as:

- Value's *GameNetworkingSockets* [@gamenetworkingsockets] allows for a pseudo-connection over `UDP` as well as allowing reliable and unreliable packets. Though the implementation includes mandatory encryption it lacks any form of compression.
- *ENet* [@enet], created for the open-source FPS *Cube* [@cube], provides, solely, reliable `UDP` packets.

When working with data where latency is not a concern, `TCP`'s built-in benefits make it a somewhat more suitable choice. For turn-based games like some 4X games such as *Civilization III* [@civ3] and board games such as *Connect Four* [@connectfour], where latency is less critical, there is argument to be made for either `TCP` (without *`Nagle's Algorithm`*) or `UDP`. When communicating with a matchmaking or account database, such as through a `RESTful` server, the benefits of `TCP`, particularly the added security, far outweigh the potential latency.

## 3.2 RESTful API

In *Architectural Styles and the Design of Network-based Software Architectures* [@fielding2000] Fielding introduces the `REpresentational State Transfer` (`REST`) architectural style. The term `RESTful` can be used to describe `HTTP-based` `API`s that meet some `REST` features but this often scrutinizes as an `API` either adherers to `REST` or does not. Most uses of the term `RESTful` actually refer to *`HTTP-based Type I`* and *`HTTP-based Type II`* [@algermissen] where neither adhere to the use of *`Hypermedia as the Engine of Application State`* defined in `REST`. The types differ in the use of *`Self-Descriptive Messages`* i.e. the use of specific media types over generic. General principles state that `REST` is superior to `Type II` which in turn is superior to `Type I`.

> "Depending on the degree to which existing media types apply to the problem domain HTTP-based Type II should be considered over HTTP-based Type I because the start-up cost is almost identical. A transition from HTTP-based Type II to REST at a later point in time, however, is rather easy."
*Classification of HTTP-based APIs* [@algermissen]

Despite this, this document uses the term `RESTful` interchangeably with `HTTP-based Type` due to the communities adoption of the term.

## 3.3 Security Algorithms

### 3.3.1 TLS

`Transport Layer Security` (`TLS`) [@rfc8446] and the similar `Datagram Transport Layer Security` (`DTLS`) are cryptographic protocols designed to provide secure communication. The protocol describes the data exchanged between the client and server in the handshake. This exchange includes the sharing of an asymmetric (public) key which is used in a key exchange to generate a symmetric session key for use in the rest of communication (i.e. with application data). The `Finished` packet includes a hash of the handshake communications using the session key thus allowing both parties to validate the exchange. The handshake also contains the exchange of certificate(s) allowing parties to validate the identity of the other party.

![A example of a TLS 1.3 full handshake including a server certificate [@wolfssl]](media/tls_1.3_handshake.png)

---

### 3.3.2 Session Keys

There are several different options for the asymmetric key used in the key exchange. The primary options (used in `TSL 1.3`) are either an `Elliptic Curve` (`EC`) or `Finite Field` (`FF`) which use an `Elliptic Curve Diffie-Hellman` (`ECDH`) and `Finite Field Diffie-Hellman` (`FFDH` or, more commonly, `DH`) key exchange respectively. Both are preferred in ephemeral (`ECDHE`, `DHE`) form meaning that keys are regenerated for each new session thus meaning the system is less venerable of replay attacks.

*The Performance of Elliptic Curve Based Group Diffie-Hellman Protocols for Secure Group Communication over Ad Hoc Networks* [@ecdh] compares the performance of `ECHD` against `DH` and finds that `EC` outperforms `DH` in, among other things, both communication time and key generation speed. As such, `ECHD(E)` is considered to be the preferred method for session key generation.

---

### 3.3.3 Authentication

The certificate used in the `TLS` handshake is typically in the form of an `X.509` [@x509] containing an identity and a public key which is signed using the respective private key. There are serval options for choice in key pair used, with the most common being `RSA` [@rsa] and `Elliptic Curve Digital Signature Algorithm` (`ECDSA`). `DSA`, though currently still used, is being phased out largely due to its comparative weakness to other algorithms. `ECDSA` offers the equivalent level of security to `RSA` with a smaller key size as well as typically faster encryption and description speeds. This can be particularly relevant with a repeated key exchange, but is less relevant in the context of `X.509` verification as this process will typically only occur once per session. Historically, `RSA` has been the de facto choice, but recent years have seen `ECDSA` grow in adoption. `RSA`'s dominance is largely associated with the algorithm's maturity and existing wide adoption and, for this reason, remains a suitable choice for `X.509` signing.
