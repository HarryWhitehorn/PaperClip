# 4 Method

## 4.0 Tools

### 4.0.1 Programming Language

The project is written in `Python`. This was a language I was most familiar with. The `Flask` package was used for the `RESTful` `API` `server` in conjunction with `SQLAlchemy` to communicate with the database.

### 4.0.2 Database

The database language chosen was `mySQL`. This was deployed in a `Docker` stack during development for convenience.

### 4.0.3 IDE

`Visual Studio (VS) Code` was chosen as the primary IDE to write `Python`. `VS Code` supports a large variety of different languages via first and third-party plug-ins which was useful when working with some of the additional file types using in this project (e.g. `.env`,  `.yaml`, `.md`). Additionally, I was reasonably experienced with creating custom `launch.json` debug configurations allowing for easy debugging of file in parallel.

### 4.0.4 Source Control

`Git` and `Github` were using throughout development for source control management. Branches were frequently used to allow for parallel implementation of different features.

## 4.1 Methodology

The methodology used thought the project was the `Agile` `Feature-Driven Development` (`FDD`) method. This was well suited to the project as it enabled for objectives to be adaptive as a better understanding of the system requirements was gained. Additionally, it allowed for features to be designed, implemented and tested in parallel, ensuring each component was working as expected, before combining into a final cohesive package.

## 4.2 Analysis

The majority of the analysis can be seen in the *literature review*. Some additional analysis, however, was performed throughout the project as each feature was implemented.

## 4.3 Design

### 4.3.1 Packet Specification

As stated in the literature review, a custom feature-rich `UDP` protocol would need to be defined. The additional features include:

- Packet Order
    - There would need to be some way for the recipient to be able to determine the order in which packets were sent thus allowing for old packets to be discarded.

- Reliability
    - There would need to be some way for a sender to be confident that the recipient had received the packet they had sent.

- Error-checking
    - Though `UDP` provides a built-in checksum, using a custom data validation method would give me both more control as well as the option to still receive corrupted packets on the application layer as the TCP checksum occurs below the application layer.

- Fragmentation
    - Packets should be able to split a packet into fragments. This would be particularly useful when sending a large amount of data via `UDP`.

- Compression
    - Packets should be able to indicate if a packet's data has been compressed thus allowing decompression to happen automatically. Though compression would be likely unpractical with typical packet traffic (likely increasing payload size), packets with large amounts of data such as fragmented packets could be compressed to reduce the number of fragments (thus reducing the number of points of failure).

- Encryption
    - Encryption would provide various benefits such as a recipient being confident in the sender as well as adding security against any attackers. It would also mitigate against packet fabrication. Packets should be able to indicate, in a similar fashion to compression, that they are encrypted so they can be decrypted automatically.

These features were formalized in a Packet Specification document

### 4.3.2 Database Models

The database models were designed using a `UML` `Entity Relationship Diagram` (`ERD`).

### 4.3.3 API Specification

When working with the `API`, the most logical implementation was to create a `RESTful` `HTTP` (`TCP`) server. Using flask, the web-server could act as a middleman for communication with the database. This allows for data sanitation, easy authorization control and easy scalability.

The `TCP` server would also be responsible for:

- Matchmaking and joining Lobbies
- Creating Lobbies (and the relevant game servers)
- Managing Accounts
    - Friends
    - Scores
- Certificate Validation

These features were formalize in an `API` Specification document.

## 4.4 Implementation

### 4.4.1 Iteration 1

The first iteration focused on setting up the basis for the custom `udp` implementation.

#### 4.4.1.1 Packet Specification Implementation

Before creating any `Client` or `Server` implementation the packet structure defined in PACKET_SPEC was implemented in class definitions with the reliant methods to convert to and from bytes.

#### 4.4.1.2 UDP Node

A base class `Node` was created. The `Node` class is responsible for sending and receiving packets.

##### 4.4.1.2.1 Client

A `Client` class was created, inheriting from `Node`. The `Client` class overrides the send methods to use a given `targetAddress`. This means that clients can be created for a specific `Server`

##### 4.4.1.2.1 Server

A `Server` class was created, inheriting from `Node`. The `Server` is initially passive waiting for and replying to incoming packets from a `Client`.

#### 4.4.1.3 DEFAULT Packet

The `DEFAULT` packet sending and receiving was implemented for `Node` using the `packet.Packet` class defined earlier.

#### 4.4.2.1 Threading

The `Client` and `Server` are refactored to allow for simultaneous sending and receiving.

`Python`'s (or more specifically `CPython`'s) `Global Interpreter Lock` (`GIL`) is a mutex that prevents multiple threads from executing `Python` bytecode at once. This mitigates against race conditions. The `GIL` is not however a catch all and some actions required additional locking.

### 4.4.2 Iteration 2

The second iteration focused on expanding the custom `UDP` implementation with a focus on implementing the authentication and security features outlined in the packet specification.

#### 4.4.1.1 Reliable Flag and ACK Packets

The `RELIABLE` flag ensures that packets are delivered. A `Node` will resend a `RELIABLE` packet until it receives acknowledgment through an ACK packet.

#### 4.4.2.2 AUTH Packets

The `AUTH` packet is used for authenticating a `Node` during the handshake. The `public key` and `certificate` fields defined in the packet specification are implementation agnostic. Ultimately, `Elliptic Curve` (`EC`) Keys were chosen for use as the key used in the `AUTH` packet. For certificates, and therefore identity verification, `X.509` in conjunction with `RSA` signing is used. The `Node` class has fields for a `X.509` certificate and `EC` Private Key whereas the `RSA` key is defined in the `Client` and `Server`.

#### 4.4.2.3 Handshake

The Handshake is loosely defined defined in the packet specification. As the key chosen for the `AUTH` packet was `EC` an `Elliptic-curve Diffie-Hellman` (`ECHD`) is used for session key generation.

#### 4.4.2.4 Flags

Each flag and is behavior is defined in packet specification. Each flag was implemented such that flag behavior's are automatically performed before sending and after reiving.

### 4.4.3 Iteration 3

The third iteration focused on finishing implementation of the features outlined in the packet specification.

#### 4.4.3.1 ACK Bits and Rolling Reset

The `Node` class was updated to use the available ack bits in the `ACK` packet's headers to provide an additional layer of reliability. Additionally, a rolling reset of the recorded ACKed bits was implemented. Without this, upon `sequenceId` wrap around, a `Node` can be misinformed about that bits have been ACKed.

#### 4.4.3.2 HEARTBEAT Packets

The `HEARTBEAT` packet sending and receiving was implemented using `packet.HeartbeatPacket`. This allows for the `Server` to remove unresponsive `Clients` in a `heartbeatThread`.

#### 4.4.3.3 Callbacks

Callbacks were implemented allowing for data to propagate through game `Server` and `Clients` as well allowing for packet data to reach the *application* layer.

#### 4.4.3.4 ERROR Packets

The `ERROR` packet sending and receiving was implemented using `packet.ErrorPacket`. Additionally, the errors outlined in the packet specification were implemented as `Exceptions` in `udp.errors`. These `Exceptions` and their relevant handling were put throughout the project.

#### 4.4.3.5 Disconnects

The `DisconnectError` is used whenever a `Node` is gracefully terminating. The implementation of the error varies between the `Client` and `Server` with `Client` terminating and the `Server` removing the `Client`.

### 4.4.4 Iteration 4

The fourth iteration focused on creating the RESTful server and the database models as well as a turn-based game demo. Finally, a end-user `client` was created.

#### 4.4.4.1 DotEnv

The `CONST`s defined across the project were consolidated into a `.env` file. This constance are then loaded at run-time using the `dotenv` package. This provided structure to the project and allowed for easier control over the various variables.

#### 4.4.4.2 Logging

Logging using the `logging` model was implemented across the package. The `logger` was set to output to both the console as well as a `paperclip.log` file. This outputs were given different 'levels' to avoid cluttering the console output while retaining all generated outputs in the log file.

#### 4.4.4.3 Database Models

The database modules defined in the `ERD` were implemented as `SQLAlchemy` `db.models` allowing the `Server` to initiate the database with the appropriate tables on start-up. Various changes were made between the design and final implementation to match the projects new requirements. These are outlined in the *Results* section.

#### 4.4.4.4 RESTful Server

The `TCP` `RESTful` `API` `Server` was implemented using as a `Flask` app. Authentication using `HTTPBasicAuth` is implemented allow for either a username and password or a session key to be used.

The endpoints for the various `API` functionalities are implemented according to the `API` specification.

#### 4.4.4.5 Certificates and Handshake

The `udp` handshake is amended to use the `RESTful` server as an authenticator for certificates. Additionally, the `udp.auth` method to generate certificates is expanded to accept and embed an `Account.id` and an `Account.username` in the certificate fields.

#### 4.4.4.6 RPS Demo

A turn-based game demo (Rock, Paper, Scissors) was created containing a game `Server` and `Client`. The `Server` is responsible for evaluating each turn sending the results to the `Client`s. The `Client` is responsible for taking a player input and sending it to the `Server` the `Client` then displays the results received.

#### 4.4.4.7 Client

A end-user command-line user-interface `client` was created. The `client` package contains wrappers for communication with `RESTful` server, including authentication. The `client` package then provides a text-based environment for a user for each `API` endpoint. The `client` is also responsible for creating a game `Client` and joining the relevant game `Server`. Finally, the matchmaking logic was implemented to allow for automatic `Lobby` joining when available.

## 4.5 Tests

The `pytest` module was used to define serval test.

## 4.6 Reused Code and Tutorials

The `client` package makes use of `inputimeout` package [@inputimeout] to allow for non-blocking inputs. This code was modified to allow prevent the automatic appending of a new line after each timeout.

A large amount of inspiration was taken from the *Reliability and Congestion Avoidance over UDP* [@fiedle-reliable], in perticualry the use of `ack_bits` in an `ACK` package.
