#!/usr/bin/python
"""
a high-level API for pluggable key derivation functions

Rather than store the algorithm and workfactor with the salt, we treat them as
additional secrets and extract them from the password.  This adds another
character to the password, but allows us to have password-encrypted data that
is indistinguishable from random data (no magic signature) without the correct
password.  

This would NOT be a good plan for a server-based hash verification.

XXX: extraction proceedure subject to change until we hit a BETA status 
(need scrypt working)

"""
__all__=[]
def _all(f):
    __all__.append(f.__name__)
    return f

try:
    from bcrypt import kdf as _bckdf 

    @_all
    def pbkdf2_bcrypt_sha512(password,salt,keybytes,workfactor):
        rounds = 1<<(workfactor+5)
        #print "using PBKDF2 with %d rounds of BcryptSHA-512" % rounds
        return _bckdf(password,salt,keybytes,rounds)

except ImportError:
    import warnings
    warnings.warn("bcrypt not available")

    def pbkdf2_bcrypt_sha512(password,salt,keybytes,workfactor):
        raise RuntimeError("unsupported algorithm")


from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha512
from hmac import HMAC

def prf_hmac_sha512(p,s):
    return HMAC(p,s,sha512).digest() 

@_all
def pbkdf2_sha512(password,salt,keybytes,workfactor):
    rounds = 1<<(workfactor+16) 
    #print "using PBKDF2 with %d rounds of SHA-512" % rounds
    return PBKDF2(password,salt,keybytes,rounds,prf_hmac_sha512) 

# TODO: figure out how to implement scrypt
def scrypt(password,salt,keybytes,workfactor):
    raise RuntimeError("unsupported algorithm")

# the first character of the password determines the KDF and the work factor
KDFS={
    1:pbkdf2_sha512, # ' '
    2:pbkdf2_bcrypt_sha512,   # 'A'
    3:scrypt, # 'a'
    }

@_all
def derive_key(password,salt,dklen):
    """ derive `dklen` bytes of key material from `password` and `salt`

    In order to make the encrypted keybox indistinguishable from random data,
    we don't store the algorithm or the workfactor in the file. Rather, we
    extract it from the first character of the password -- an additional secret.

    """
    whichkdf = ord(password[0])>>5
    workfactor = ord(password[0])&31

    kdf = KDFS.get(whichkdf)
    if kdf is None:
        raise RuntimeError("unsupported algorithm")

    return kdf(password[1:],salt,dklen,workfactor)


if __name__=="__main__":
    from binascii import b2a_base64 as e64
    
    from getpass import getpass
    try:
        while True:
            pw = getpass("please enter a password:")
            print(pw)
            dkey = derive_key(pw,"NaCl",32)
            print(e64(dkey))
    except KeyboardInterrupt:
        print("goodbye")

