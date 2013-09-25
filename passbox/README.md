
PassBox
=======

A generic box encrypted with a password-derived key.

To provide some limited plausible deniablility we do not store the kdf
parameters in the keyfile.  This allows us to create a keyfile that is
indistinguishable from random data without the correct password. Extracting the
algorithm and parameters from the password itself also makes the work of an
attacker much more difficult. Without knowing the first character of the
password, the attacker has to try *all* combinations of algorithm and work
factor for every password guess. Making bcrypt and scrypt available as KDFs as
well as PBKDF2-SHA512 raises the bar considerably.

I adapted this code to depend only on PyCrypto. Pynacl/libsodium gives a
smaller file with faster operations, but may be an unacceptable dependency for
some projects. It may stil be used with nacl, but the application must be 
able to correctly discern which algorithm is used, as there is no magic in
the keyfile itself. One possibility is by length.  A better strategy is to
choose one and stick with it.

TODO
----
* RFC 4013 processing for unicode passwords
* unicode/python3
