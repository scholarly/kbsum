#!/usr/bin/python
"""
creates and reads a password-protected keyfile

test code allows symmetric encryption/decryption of named file using masterkey
stored in keyfile.

"""

import os
from kdf import derive_key

from pinentry import pinentry

SALT_SIZE = 32

# XXX need to do sasl stringprep on password

class KeyBox(object):
    def __init__(self,box,random):
        self.random = random
        self.box = box

    def wrapkey(self, password, key ):
        """encrypt a key using a password-derived key
        """
        salt = self.random(SALT_SIZE)
        kek = derive_key(password,salt,self.box.KEY_SIZE)
        sbox = self.box(kek)
        nonce = self.random(sbox.NONCE_SIZE)
        payload = sbox.encrypt(key,nonce)
        return salt+payload

    def unwrapkey(self, password, wrapped ):
        """decrypt the key encrypted by the password-derived key 
        """
        salt = wrapped[:SALT_SIZE]
        payload = wrapped[SALT_SIZE:]
        kek = derive_key(password,salt,self.box.KEY_SIZE)
        sbox = self.box(kek)
        return sbox.decrypt(payload)


class KeyFile(KeyBox):
    def __init__(self,box,random,fname,pe=pinentry):
        super(KeyFile,self).__init__(box,random)
        self.keyfilename = fname
        self.pinentry = pe
        self.__sb = None

    def open(self):
        if os.path.exists(self.keyfilename):
            with open(self.keyfilename,"rb") as keyfile:
                ctext = keyfile.read()#KEYFILE_SIZE)
                masterkey = self.pinentry( "Please enter your master password to unlock your keyfile.",
                    lambda p: self.unwrapkey(p,ctext))
        else:
            kekey = self.pinentry( "Please enter a new master password to protect your keyfile.",None,True)
            masterkey = self.random(self.box.KEY_SIZE)
            with open(self.keyfilename,"wb") as keyfile:
                keyfile.write(self.wrapkey(kekey,masterkey))

        self.__sb = self.box(masterkey)
        return self.__sb
             

    def lock(self):
        # XXX there should be more to this, but python doesn't give us secure erasure
        self.__sb = None 

    def encode(self,pw):
        sb = self.__sb or self.open()
        return sb.encrypt(pw.encode("utf8"),self.random(sb.NONCE_SIZE))
        
    def decode(self,ctext):
        sb = self.__sb or self.open()
        return sb.decrypt(ctext)
        


if __name__=="__main__":
    import Crypto.Random
    from secret import SecretBox
    random = Crypto.Random.new().read

    import sys
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-c",action="store_true",default=False)
    p.add_argument("keyfile")
    p.add_argument("source")
    p.add_argument("target")

    opt = p.parse_args()
    print(opt)

    keybox = KeyFile(SecretBox,random,opt.keyfile)

    with open(opt.source,"rb") as fin:
        text = fin.read()

    try:

        if opt.c:
            out = keybox.encode(text)
        else:
            out = keybox.decode(text)
    except KeyboardInterrupt:
        sys.exit(1)

    with open(opt.target,"wb") as fout:
        fout.write(out)

