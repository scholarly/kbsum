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
"""
__all__=[]
def _all(f):
    __all__.append(f.__name__)
    return f

try:
    from bcrypt import kdf as _bckdf 

    @_all
    def pbkdf2_bcrypt_sha512(password,salt,dklen):
        """ derive `dklen` bytes of key material from `password` and `salt`

        log2(rounds) is extracted from the first byte of password
        """
        rounds = 1<<((ord(password[0])&31)+5)
        #print "using PBKDF2 with %d rounds of BcryptSHA-512" % rounds
        return _bckdf(password[1:],salt,dklen,rounds)

except ImportError:
    import warnings
    warnings.warn("bcrypt not available")

    def pbkdf2_bcrypt_sha512(password,salt,dklen,workfactor):
        raise RuntimeError("unsupported algorithm: bcrypt not available")


from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha512
from hmac import HMAC

def prf_hmac_sha512(p,s):
    return HMAC(p,s,sha512).digest() 

@_all
def pbkdf2_sha512(password,salt,dklen):
    """ derive `dklen` bytes of key material from `password` and `salt`

    log2(rounds) is extracted from the first byte of password
    """
    rounds = 1<<((ord(password[0])&31)+16) 
    #print "using PBKDF2 with %d rounds of SHA-512" % rounds
    return PBKDF2(password[1:],salt,dklen,rounds,prf_hmac_sha512) 


try:
    from scrypt import hash as _skdf
    @_all
    def scrypt(password,salt,dklen):
        """ derive `dklen` bytes of key material from `password` and `salt`

        scrypt parameters N r p are extracted from the first two bytes of the password

        """
        N,r,p = decode_scrypt_params(password)
        return _skdf(password[2:],salt,N,r,p,dklen)

    def decode_scrypt_params(pw):
        N = 1<<((ord(pw[0])&31)+10)# min: 1MiB max: unreasonable 
        rp = (ord(pw[1])-32)&0x7f # [ -~] is 95 characters
        r = 1<<((rp&15)+3)
        p = 1<<((rp>>4))
        return N,r,p


    def log2(n):
        nn=n
        for i in range(32):
            if nn&1:
                if (nn&-2):
                   raise ValueError("not a power of 2",n) 
                return i
            nn>>=1
        raise ValueError("out of range")

    def encode_scrypt_params(N,r,p):
        # TODO: do some more sanity checks 
        # e.g. using more than a GiB of RAM is currently unreasonable

        logN = log2(N)-10
        if logN<0 or logN>31:
            raise ValueError("N out of range",N)

        logr = log2(r)-3
        if logr<0 or logr>15:
            raise ValueError("r out of range",r)

        logp = log2(p)
        if logp<0 or logp>8:
            raise ValueError("p out of range",p)

        return chr(logN+96)+chr(logr+(logp<<4)+32)


except ImportError:
    @_all
    def scrypt(password,salt,dklen):
        raise RuntimeError("unsupported algorithm: scrypt not available")

# the first character of the password determines the KDF and the work factor
KDFS={
# 3 blocks of 32 printable ascii characters
    1:pbkdf2_sha512, # [ -?] ' !"#$%&\'()*+,-./0123456789:;<=>?' 
    2:pbkdf2_bcrypt_sha512,   # [@-_] '@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'
    3:scrypt, # [`-~] '`abcdefghijklmnopqrstuvwxyz{|}~'
    }

@_all
def derive_key(password,salt,dklen):
    """ derive `dklen` bytes of key material from `password` and `salt`

    In order to make the encrypted keybox indistinguishable from random data,
    we don't store the algorithm or the workfactor in the file. Rather, we
    extract it from the first character of the password -- an additional secret.

    """
    whichkdf = ord(password[0])>>5

    kdf = KDFS.get(whichkdf)
    if kdf is None:
        raise RuntimeError("unsupported algorithm")

    return kdf(password,salt,dklen)


if __name__=="__main__":
    from binascii import b2a_base64 as e64
    import time
    
    from getpass import getpass
    try:
        while True:
            pw = getpass("please enter a password:")
            print(pw)
            start = time.clock()
            dkey = derive_key(pw,"NaCl",32)
            elapsed = time.clock()-start
            print("{0:0.3f} seconds {1}".format(elapsed,e64(dkey)))
    except KeyboardInterrupt:
        print("goodbye")

