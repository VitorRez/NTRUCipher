from PyNTRU.ntru.NTRU import *
from PyNTRU.certificate import *

class Signature:

    def __init__(self, priv_key=0, pub_key=0):
        self.priv_key = priv_key
        self.pub_key = pub_key

    def sign(self, msg):
        if type(msg) != bytes:
            msg = msg.encode('utf-8') 
        return sign(self.priv_key, self.pub_key, msg)
    
    def verify(self, msg, s):
        return verify(self.pub_key, msg, s)
    
        
    