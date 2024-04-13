from node import *

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
    
if __name__ == "__main__":
    nodeSequenceIdLock()