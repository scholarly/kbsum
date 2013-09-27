#!/usr/bin/python
"""
creates and reads a password-protected keyfile

test code allows symmetric encryption/decryption of named file using masterkey
stored in keyfile.

"""

import os
from passbox.kdf import derive_key

from passbox.pinentry import pinentry

SALT_SIZE = 32


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
        return sb.encrypt(bytes(pw),self.random(sb.NONCE_SIZE))
        
    def decode(self,ctext):
        sb = self.__sb or self.open()
        return sb.decrypt(ctext)
        

def main(*args):
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-c",action="store_true",default=False,help="encrypt source file (default:decrypt)")
    p.add_argument("-d",dest="c",action="store_false",help="decrypt source file (default)")
    p.add_argument("-n",action="store_true",default=False,help="use NaCl instead of Crypto")
    p.add_argument("keyfile",help="store or read symetric key here")
    p.add_argument("source", help="read data from SOURCE")
    p.add_argument("target", help="write data to TARGET")

    opt = p.parse_args(args)
    #print(opt)

    if opt.n:
        from nacl.utils import random
        from nacl.secret import SecretBox
    else:
        import Crypto.Random
        from secret import SecretBox
        random = Crypto.Random.new().read
        
    keybox = KeyFile(SecretBox,random,opt.keyfile)

    with open(opt.source,"rb") as fin:
        text = fin.read()

    try:
        if opt.c:
            out = keybox.encode(text)
        else:
            out = keybox.decode(text)
    except KeyboardInterrupt:
        raise SystemExit(1)

    with open(opt.target,"wb") as fout:
        fout.write(out)

if __name__=="__main__":
    import sys
    main(*sys.argv[1:])
