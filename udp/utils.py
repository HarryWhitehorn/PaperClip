import zlib

from . import MAX_FRAGMENT_SIZE

def compressData(data:bytes) -> bytes:
    # default speed
    # no header or checksum
    return zlib.compress(data, -1, -15)

def decompressData(data:bytes) -> bytes:
    # no header or checksum
    return zlib.decompress(data, -15)

def generateChecksum(data:bytes) -> int:
    return zlib.crc32(data)

def fragmentData(data:bytes) -> list[bytes]:
    return [data[i:i+MAX_FRAGMENT_SIZE] for i in range(0,len(data),MAX_FRAGMENT_SIZE)]

def defragmentData(fragments:list[bytes]):
    return b"".join(fragments)

if __name__ == "__main__":
    import os
    d = generateChecksum(os.urandom(16))
    print(d)