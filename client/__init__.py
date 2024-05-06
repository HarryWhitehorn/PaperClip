import os
import sys

import dotenv

from udp import logger, logging

dotenv.load_dotenv()

TCP_HOST = os.environ.get("S_HOST")
TCP_PORT = int(os.environ.get("TCP_PORT"))
C_PORT = int(os.environ.get("C_PORT"))
SERVER_URL = f"http://{TCP_HOST}:{TCP_PORT}"

offset = sys.argv[1:]
try:
    offset = int(offset[0])
except ValueError:
    offset = None
except IndexError:
    offset = None

if os.environ.get("DEBUG") is not None:
    logger.setLevel(logging.WARNING)
    while offset is None:
        try:
            offset = int(input("\noffset: "))
        except ValueError:
            print("Invalid input.")
else:
    logger.setLevel(logging.ERROR)

if offset is not None:
    C_PORT += offset
