#!/usr/bin/python3
'''
Karnauch, Andrey
CS483 - rsa_validate.py
Validates a given RSA integer using public key
'''
from cs483 import signIO
import sys
import hashlib

'''
@param n, nbits: the public key N and its bit size
@param key: the inverse multiplicative mod of priv key d
@param m: the base10 integer to decrypt
@return: the base10 integer representing a message
'''
def dec(nbits, n, key, m):
    m_inv = pow(m, key, n)
    return m_inv

if __name__ == "__main__":
    args = signIO.parse()
    m = signIO.getInput(args)
    sig = signIO.getSig(args)
    nbits, n, key = signIO.getKey(args)
    sig_dec = dec(int(nbits), int(n), int(key), int(sig))

    m_hash = hashlib.sha256(m.encode())
    digest = int.from_bytes(m_hash.digest(), sys.byteorder)
    if (digest == sig_dec):
        print("True")
    else:
        print("False")
