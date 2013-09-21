#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA256

from padding import enpad,unpad

class SecretBox(object):
    """
    An incomplete substitute for the SecretBox in nacl.secret

    This allows similar functionality while depending only on PyCrypto

    Crypto.Cipher.AES doesn't currently support MODE_GCM, so we use
    HmacWithSha256 on the ciphertext. Therefore, we need an extra key for the
    HMAC.

    """
    _cipher = AES
    _hash = SHA256
    KEY_SIZE = _hash.digest_size+_cipher.key_size[-1]
    NONCE_SIZE=_cipher.block_size

    def __init__(self,key):
        klen = len(key)
        if klen != self.KEY_SIZE:
            raise ValueError("key must be exactly {0:d} bytes long".format(self.KEY_SIZE))
            
        hklen = klen-self._hash.digest_size

        self.__hkey = key[:hklen]
        self.__key = key[hklen:]

    def encrypt(self,plaintext,nonce):
        if len(nonce)!=self.NONCE_SIZE:
            raise ValueError("nonce must be exactly {0:d} bytes long (not {1:d})".format(self.NONCE_SIZE,len(nonce)))

        c = self._cipher.new(self.__key,self._cipher.MODE_CBC,nonce)
        ct = c.encrypt(enpad(plaintext,c.block_size))

        mac = HMAC.new(self.__hkey,"",self._hash)
        mac.update(nonce)
        mac.update(ct)

        return nonce+ct+mac.digest()


    def decrypt(self,ciphertext,nonce=None):
        if nonce is None:
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce)!=self.NONCE_SIZE:
            raise ValueError("nonce must be exactly {0:d} bytes long".format(self.NONCE_SIZE))

        maclen = self._hash.digest_size
        l = len(ciphertext) - maclen
        cdigest = ciphertext[l:]
        ciphertext = ciphertext[:l]

        mac = HMAC.new(self.__hkey,nonce,self._hash)
        mac.update(ciphertext)
        mdigest = mac.digest()

        cipher = self._cipher.new(self.__key,self._cipher.MODE_CBC,nonce)
        plaintext = unpad(cipher.decrypt(ciphertext),cipher.block_size)

        # we check the mac after decrypting to mitigate timing attacks
        c = 0
        for o,m in zip(cdigest,mdigest):
            c|=ord(o)^ord(m)
        if c!=0:
            raise ValueError("decryption failed")

        return plaintext


if __name__=="__main__":
    import sys

    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-c",action="store_true",default=False)
    p.add_argument("keyfile")
    
    opt = p.parse_args()

    with open(opt.keyfile) as kf:
        intext = sys.stdin.read()
        masterkey = kf.read(SecretBox.KEY_SIZE)
        sb = SecretBox(masterkey)
        if opt.c:
            nonce = kf.read(SecretBox.NONCE_SIZE)
            out = sb.encrypt(intext,nonce)
        else:
            out = sb.decrypt(intext)
        sys.stdout.write(out)

