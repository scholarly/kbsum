
#import passbox.kdf
from passbox.kdf import derive_key

SALT = b"NaCl"

def check_badalgorithm(pw):
    try:
        k = derive_key(pw,SALT,16)
        assert False,"{} should not be valid".format(pw)
    except RuntimeError:
        pass

def test_bad():
    for x in range(32):
        yield check_badalgorithm, chr(x)
    for x in range(128,256):
        yield check_badalgorithm, chr(x)
        
def test_pbkdf2():
    k = derive_key(" aaa",SALT,16)

def test_bcrypt():
    k = derive_key("@aaa",SALT,16)

def test_scrypt():
    k = derive_key("`aaa",SALT,16)

