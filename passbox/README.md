
PassBox
=======

A generic box encrypted with a password-derived key.

To provide some limited plausible deniablility we do not store the kdf
parameters in the keyfile.  This allows us to create a keyfile that is
indistinguishable from random data without the correct password. Extracting the
algorithm and parameters from the password itself also makes the work of an
attacker much more difficult. Without knowing the first character of the
password, the attacker has to try *all* combinations of algorithm and work
factor for every password guess. Making bcyrpt and scrypt available as KDFs as
well as PBKDF2-SHA512 raises the bar considerably.

I adapted this code to depend only on PyCrypto. Pynacl/libsodium gives a
smaller file with faster operations, but may be an unacceptable dependency for
some projects.

TODO
----
RFC 4013 processing for unicode passwords
scrypt
unicode/python3
