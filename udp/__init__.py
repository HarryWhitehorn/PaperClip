import logging
import sys

__version__ = 0

S_HOST = "127.0.0.1"
S_PORT = 2024
C_HOST = "127.0.0.1"
C_PORT = S_PORT+1

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ColorFilter(logging.Filter):
    colorCodes = [getattr(bcolors, attr) for attr in dir(bcolors) if not attr.startswith("__")]
    
    def filter(self, record: logging.LogRecord) -> bool:
        for color in self.colorCodes:
            record.msg = record.msg.replace(color, "")
        return True
    
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

printHandler = logging.StreamHandler(sys.stdout)
printHandler.setLevel(logging.INFO)
logger.addHandler(printHandler)

fileHandler = logging.FileHandler("udp.log")
fileHandler.setLevel(logging.DEBUG)
fileHandler.addFilter(ColorFilter())
fileHandler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(fileHandler)