
from passbox.padding import enpad,unpad

def check_pad(text,bs):
    p = enpad(text,bs)
    u = unpad(p,bs)
    assert (len(p)%bs)==0
    assert u == text

def test_padding():
    f = b"soup is good\x80 food."
    for x in range(len(f)+1):
        yield check_pad, f[:x], 16

def test_double():
    a = b"hello"
    b = enpad(a,16)
    c = enpad(b,16)
    d = unpad(c,16)
    assert b==d
    e = unpad(d,16)
    assert a==e

def test_evil():
    a = b'aaaaaaaaaaaaaa\x80a'
    b = unpad(a,16)
    assert b is None
