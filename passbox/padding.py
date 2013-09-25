#!/usr/bin/python
"""
padding method for block ciphers

Standardized as "padding method 2" in ISO/IEC 9797-1
see https://en.wikipedia.org/wiki/Block_cipher#Padding

"""

def enpad(text,blocksize):
    """pad text to a multiple of blocksize bytes

    Add a one-bit and then extend the last block with zero-bits.
    Standardized as "padding method 2" in ISO/IEC 9797-1

    see https://en.wikipedia.org/wiki/Block_cipher#Padding
    """
    need = blocksize-(len(text)%blocksize)-1
    return text + b'\x80'+b'\0'*need


def _mkunpad():
    import sys
    if sys.version_info < (3,0):
        PAD_FIRST = b'\x80'
        PAD_ZERO = b'\0'
    else:
        PAD_FIRST = 128
        PAD_ZERO = 0

    def unpad(text,blocksize):
        """remove padding added by enpad

        Searches the last blocksize bytes for the last '\x80' byte.

        If the ciphertext is corrupted or the key is wrong, we will probably get
        bad padding here.
        
        """
        tlen = len(text)
        end = -1
        nonzero = -1 
        start=tlen-blocksize
        for i in range(start,tlen):
            # XXX careful of timing attacks
            end = i if text[i]== PAD_FIRST else end
            nonzero = i if text[i]!=PAD_ZERO else nonzero

        #print (end,nonzero)
        invalid = int(end<0) | int(end<nonzero)
        return None if invalid else text[:end]  
    return unpad

unpad = _mkunpad()


if __name__=="__main__":
    import Crypto.Random
    random = Crypto.Random.new().read
    from binascii import b2a_hex as hx

    f = b"soup is good\x80 food."
    for x in range(len(f)+1):
        e = f[:x]
        p = enpad(e,16)
        u = unpad(p,16)
        if u!=e:
            print(len(e),hx(e))
            print(len(p),hx(p))
            print(repr(u))

    block = random(32)

    from hashlib import sha256
    m = sha256(block)

    for x in range(15):
        k = m.digest()
        m.update(k)
        l = unpad(k,16)
        if l is not None:
            print(hx(k))
            print(hx(l))

