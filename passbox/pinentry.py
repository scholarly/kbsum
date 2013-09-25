#!/usr/bin/python
"""
A slightly higher-level API to access getpass.

Feel free to implement your own UI for the same protocol.

"""

import sys

if sys.version_info < (3,0):
    from getpass import getpass as _gp
    def getpass(*args,**kw):
        return unicode(_gp(*args,**kw))
else:
    from getpass import getpass 

__all__=["pinentry"]

def pinentry(prompt,check,new=False):
    """prompt the user for a password, check it for validity
    """
    sys.stderr.write(prompt+"\n")
    while True:
        # KeyboardInterrupt will also exit this loop
        passwd = getpass("enter password:")
        if new:
            pass2 = getpass("confirm password:")
            if passwd != pass2:
                sys.stderr.write("Passwords don't match. Please try again.\n")
                continue
        try:
            if check is None:
                return passwd
            else:
                return check(passwd) 
        except Exception as e:
            sys.stderr.write("{0}\nThat doesn't seem to be quite right. Please try again.\n".format(e))


if __name__=="__main__":
    pw = pinentry("Please enter a new password",None,True)
    print("got it")

    # time passes

    def check(p):
        if p != pw:
            raise ValueError("bad password")

    pw2 = pinentry("Pretend it is later: enter it again",check)
    print("ok")
