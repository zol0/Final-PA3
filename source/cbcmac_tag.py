#!/usr/bin/python3.5
'''
Karnauch, Andrey
CS483 - cbcmac_tag.py
Tags a message using CBC mode
'''
import sys
import math
from cs483 import AESHelper
from cs483 import tagIO
from Crypto import Random

BSIZE = 16

'''
Encrypts string
@param a: an AESHelper object that calls AES ECB functions
@param plain: a byte string of plaintext that is already padded
@return: a byte string that is padded and fully encrypted 
'''
def cbcenc(a,plain):

    size = len(plain)
    byte_size = int(math.ceil(size.bit_length()/8))
    while(byte_size % 16 != 0): byte_size += 1
    cipher = a.encrypt(size.to_bytes(byte_size, sys.byteorder))

    i = 0
    while (i < len(plain)):
        pXORiv = a.xor(plain[i:i+BSIZE],cipher)
        cipher = a.encrypt(pXORiv)
        i += BSIZE

    return cipher

if __name__ == "__main__": #Processes input, pads, encrypts, and prints to file

    key = tagIO.getKey()
    msg = tagIO.getInput()

    a = AESHelper.AESHelper(key)

    pad_msg = a.pad(msg)
    result = cbcenc(a, pad_msg)

    with open(tagIO.args.tag_file, "wb") as w:
        w.write(result)
