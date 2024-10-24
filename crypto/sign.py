from crypto.ntru.NTRU import *
from crypto.ntru.ntrusign import NtruSign

class signature:
    def __init__(self, priv_key=0, pub_key=0):
        self.priv_key = priv_key
        self.pub_key = pub_key

    def sign(self, msg):
        if type(msg) != bytes:
            msg = msg.encode('utf-8') 
        return sign(self.priv_key, self.pub_key, msg)
    
    def verify(self, msg, s):
        if verify(self.pub_key, msg, s):
            print('Valid signature.')
            return True
        else:
            print('Invalid signature.')
            return False