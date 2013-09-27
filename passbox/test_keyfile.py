
import tempfile
import os
import shutil
from contextlib import contextmanager

@contextmanager
def tempdir(*args):
    dirname = tempfile.mkdtemp(*args)
    try:
        yield dirname
    finally:
        shutil.rmtree(dirname)

try:
    unicode
except NameError:
    unicode = str


from passbox.keyfile import KeyFile


def static_pin(pw):
    def static_pe(prompt,check,new=False):
        return pw if check is None else check(pw)
    return static_pe
pinentry = static_pin(unicode("AllPasswords"))
plaintext=b"Guido van Rossum is a space alien"

def test_keyfile():

    with tempdir() as tmpdir:
        keyfilename = os.path.join(tmpdir,"key")

        from passbox.secret import SecretBox
        import Crypto.Random
        random = Crypto.Random.new().read

        keyfile = KeyFile(SecretBox,random,keyfilename,pinentry)
        ctext = keyfile.encode(plaintext)

        keyfile = KeyFile(SecretBox,random,keyfilename,pinentry)
        dtext = keyfile.decode(ctext)
        assert dtext==plaintext
        

def test_keyfile_nacl():
    with tempdir() as tmpdir:
        keyfilename = os.path.join(tmpdir,"key")
    
        from nacl.secret import SecretBox
        from nacl.utils import random
          
        keyfile = KeyFile(SecretBox,random,keyfilename,pinentry)
        ctext = keyfile.encode(plaintext)

        keyfile = KeyFile(SecretBox,random,keyfilename,pinentry)
        dtext = keyfile.decode(ctext)
        assert dtext==plaintext
