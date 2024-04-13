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
