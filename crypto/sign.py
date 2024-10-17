from crypto.ntru.NTRU import *
from crypto.ntru.ntrusign import NtruSign

class signature:
    def __init__(self, keys):
        self.keys = keys

    def sign(self, message):
        s = sign(self.keys[0], self.keys[1], message)
        return s
    
    def verify(self, msg, s, key):
        if verify(key, msg, s):
            print('Valid signature.')
            return True
        else:
            print('Invalid signature.')
            return False