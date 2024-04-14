from node import *
import auth

def nodeSequenceIdLock():
    n = Node(C_HOST, C_PORT)
    l = threading.Lock()
    
    def test():
        for _ in range(100000):
            n.incrementSequenceId()
            
    threads = [threading.Thread(target=test) for _ in range(10)]
    
    for t in threads:
        t.start()
        
    for t in threads:
        t.join()
    
    assert n.sequenceId == 16960, n.sequenceId
    
def sessionKey():
    localKey = auth.generateEcKey()
    peerKey = auth.generateEcKey()
    localSessionKey = auth.generateSessionKey(localKey, peerKey.public_key())
    peerSessionKey = auth.generateSessionKey(peerKey, localKey.public_key())
    assert localSessionKey == peerSessionKey

def encryptDecrypt(inputText=b"Hello World"):
    localKey = auth.generateEcKey()
    peerKey = auth.generateEcKey()
    sessionKey = auth.generateSessionKey(localKey, peerKey.public_key())
    #
    localCipher, iv = auth.generateCipher(sessionKey)
    cipherText = auth.encryptBytes(localCipher, inputText)
    #
    peerCipher, _ = auth.generateCipher(sessionKey, iv)
    outputText = auth.decryptBytes(peerCipher, cipherText)
    #
    assert inputText == outputText, (inputText, outputText)

if __name__ == "__main__":
    print(f"{'-'*5}START test(s){'-'*5}")
    # nodeSequenceIdLock()
    sessionKey()
    # encryptDecrypt()
    print(f"{'-'*5}END test(s){'-'*5}")
    