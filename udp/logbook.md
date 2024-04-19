# Logbook

## Sat 13

- Reworked `Client` and `Server` to use base `Node`
- Work on `ACK` packet
    - now includes `ACK bits` but `Node` does not use this information
    - TODO: implement resending
        - now will resend any `RELIABLE` packets where there is no record of `ACK`
    - TODO: implement rolling ack pointer for indicating newest `ACK`
    - TODO: implement rolling reset on old bits
- Added threading
    - concurrent listing and sending
- Added send buffer
    - TODO: implement smart rate limiting based on RT times to help with congestion.
- Added colored prints
    - TODO: implement proper logging with appropriate log levels

## Sun 14

- Work on `Auth` packet
    - Auth uses `ECDHE` (Elliptic Curve Diffie-Hellman Key Exchange) for creation of session keys (encryption) and `RSA` for signing (identity verification).
        - <https://digitalcommons.unl.edu/cgi/viewcontent.cgi?article=1100&context=cseconfwork> paper on speed of `ECHDE` vs `DH`
    - TODO: use ephemeral form for forward secrecy
    - TODO: random bytes in packet for use in finished and implement `finishedLabel` and `messages` for `Node.queueAuthPacket`
    - TODO: handle `auth` handshake `ACK` (enable repeat send on failure / disable repeat reiving)

## Mon 15

- Work on handshake
    - Flow:
        - `Client` starts handshake with `Auth` packet
        - `Server` receives `Auth` and generates `sessionKey`
            - `Server` returns `Auth` and `Ack` with finished as data (`sessionKey` validation)
        - `Client` receives `Auth` and generates `sessionKey`
            - `Client` send `Ack` with finished as data (`sessionKey` validation)
        - Client receives `Ack` and validates `sessionKey`
    - TODO: certification validation
    - TODO: abort if any checks fail
    - `Server` stores info on each client
        - `addr`
        - `sessionKey`
        - `handshake` success
        - TODO: heartbeat to kill dead clients. Check session key?
    - `Server` will not allow for a `client` to communicate without completing handshake
    - Created [packet spec](packet_spec.pdf) `ver 0`

## Tue 16

- Complete `packet` refactor to meet new specs.
    - `pack` and `unpack` still yield the same value (`packet to bytes` and `bytes to packet`).
    - `node` has been adjusted to still work. (Mostly using keyword for packet creation).
    - A few test to check new `packet` structure.
- Tested `ack`
    - New `packet.lazyFlags(*flags:Type)` function that returns a valid flag array with all given flags set.

## Wed 17

- Implemented `ENCRYPT` flag.
    - Data is automatically encrypted on sending and decrypted on receiving if the flag is set.
- Implemented  `COMPRESS` flag.
    - Data is automatically compressed using standard `zlib` library (standard speed, no header or checksum) and decompressed on send and receive if flag set.
- Implemented `CHECKSUM` flag.
    - Checksum (CRC32) is automatically set on sending and validated on receiving if flag set.
    - TODO: send `ERROR` on checksum fail.
- `util.py` handles compression/decompression and checksum generation.
- Created more tests.

## Thurs 18

- Refactored `Node`.
    - `Server` now uses `Nodes` to track client information.
        - Each client has its own send thread (thus `seqId`).
        - `ecKey` now unique for every client and reset for on every new handshake.
- Implemented rolling reset for `recvAckBits`.
- Encode last 16 bits into `ACK` packet (such that `[ack_id-1, ack_id-2, ack_id-3...ack_id-17]`).
    - On receiving an `ACK` packet the `Node` will now set all bits from the `ack_bits`, in addition to the `ack_id`, to `True` (mitigating against lost `ACK` packets).
- Tested both whole `Packet` loss (incoming) and `ACK` loss (outgoing) and validated that the sending acted accordingly (i.e. resend lost `Packets` and used `ack_bits` for lost `ACKs`).
- Implemented `Heartbeat` packet.
    - `Heartbeat` is sent with `heartbeat=False` to indicate `PING`. A `PING` **MUST** be replied to with a `Heartbeat` packet with `heartbeat=True` to indicate `PONG`.
    - The sever polls all clients every `HEARTBEAT_MIN_TIME` (30 seconds) and either sends a `PING` `if heartbeat delta > HEARTBEAT_MIN_TIME` **OR** drops `client` `if heartbeat delta > HEARTBEAT_MAX_TIME` (60 seconds) where `heartbeat delta = now() - last contact` in seconds.
