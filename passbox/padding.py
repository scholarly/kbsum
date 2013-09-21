def enpad(text,blocksize):
    """pad text to a multiple of blocksize bytes

    Add a one-bit and then extend the last block with zero-bits.
    Standardized as "padding method 2" in ISO/IEC 9797-1

    see https://en.wikipedia.org/wiki/Block_cipher#Padding
    """
    need = blocksize-(len(text)%blocksize)-1
    return text + '\x80'+'\0'*need

def unpad(text,blocksize):
    """remove padding added by enpad

    Searches the last blocksize bytes for the last '\x80' byte.
    We COULD check for all zero bytes after that, but I am feeling lazy.
    """
    tlen = len(text)
    end = None
    start=tlen-blocksize
    for i in range(start,tlen):
        if text[i]=='\x80':
            # no timing attacks
            end = i
    return None if end is None else text[:end]  
