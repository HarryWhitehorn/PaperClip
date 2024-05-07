# PaperClip

## Note

This software includes code that is based on or derived from `inputimeout`, a project by `johejo` available on [GitHub](https://github.com/johejo/inputimeout). The original code is licensed under the MIT License. Modifications have been made to the original code to prevent `win_inputimeout` from automatically appending a newline.

## Requirements

Requires: `python 3.11+`, `mysql server`

## mysql

A mysql server must be set up. The connection path must then be set as `SQLALCHEMY_DATABASE_URI` in the `.env`. For convenience, the following is a example docker-compose to set up a mysql server and adminer. This is the method use in testing thus the example path set in the `.env`.

```yaml
# docker-compose.yaml
version: '3.1'

services:

  adminer:
    image: adminer
    ports:
      - 8080:8080

  db:
    image: mysql:5.6
    environment:
      MYSQL_ROOT_PASSWORD: root
    ports:
      - 3306:3306
```

## Python

### Setup

Optional: `python -m venv env` and activate

Install packages: `pip install -r requirements.txt`

#### Env

Example `.env`, **must** be place in app root

``` bash
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
FLASK_APP=server
PRUNE_TIME = 58
SECRET_KEY = MyVerySecretKey
SQLALCHEMY_DATABASE_URI = mysql://root:root@localhost:3306/paperclip

# debug
DEBUG = True
```

### Run

Server: `python -m flask run`

Client: `python -m client` or `python -m client offset` (where `offset` is some `int` such that `C_PORT` (from `.env`) becomes `C_PORT+=offset`)

Tests: `pytest -v` (Note: may take some time with no output due to testing of thread locks)
