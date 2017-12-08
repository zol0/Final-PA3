#!/usr/bin/python3
from cs483 import AESHelper
from cs483 import IO
from Crypto import Random

BSIZE = 16

def cbcenc(a,plain,iv):

    pXORiv = a.xor(plain[:16],iv)
    finalCipher = iv
    i = BSIZE;

    cipher = a.encrypt(pXORiv)

    finalCipher += cipher

    while (i < len(plain)):
        pXORiv = a.xor(plain[i:i+BSIZE],cipher)
        cipher = a.encrypt(pXORiv)
        finalCipher += cipher
        i += BSIZE

    return finalCipher

if __name__ == "__main__":

    key = IO.getKey()
    msg = IO.getInput()

    a = AESHelper.AESHelper(key)

    iv = IO.getIV()
    if (iv == None):
        iv = Random.new().read(BSIZE)

    pad_msg = a.pad(msg)
    result = cbcenc(a, pad_msg, iv)

    with open(IO.args.output_file, "wb") as w:
        w.write(result)

