from PyNTRU.ntru.NTRU import *
from PyNTRU.certificate import *

class Signature:

    def __init__(self, ntru_key):
        self.ntru_key = ntru_key

    def sign(self, pub_key, msg):
        if type(msg) != bytes:
            msg = msg.encode('utf-8') 
        return sign(self.ntru_key, pub_key, msg)
    
    def verify(self, s):
        return verify(self.ntru_key, s[0], s[1])
    
        
    