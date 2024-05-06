import logging
import os
import sys

import dotenv

__version__ = 0

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


class ColorFilter(logging.Filter):
    colorCodes = [
        getattr(bcolors, attr) for attr in dir(bcolors) if not attr.startswith("__")
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        for color in self.colorCodes:
            record.msg = record.msg.replace(color, "")
        return True


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

printHandler = logging.StreamHandler(sys.stdout)
printHandler.setLevel(logging.INFO)
printHandler.setFormatter(
    logging.Formatter(f"{bcolors.OKBLUE}%(threadName)s{bcolors.ENDC} - %(message)s")
)
logger.addHandler(printHandler)

fileHandler = logging.FileHandler("paperclip.log")
fileHandler.setLevel(logging.DEBUG)
fileHandler.addFilter(ColorFilter())
fileHandler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
)
logger.addHandler(fileHandler)
