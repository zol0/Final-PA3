#!/usr/bin/python3.5
'''
Karnauch, Andrey
CS483 - rsa_sign.py
Computes an RSA signature for a message
'''
from cs483 import signIO
import hashlib
import random
import sys
import os

'''
Encrypts an element (base10 integer) in Z*_n
Message is hashed first
@param n, nbits: the public key N and its bit size
@param m, key: the base10 int to be encrypted and the priv key d
@return: m raised to the d -- m^d
'''
def sign(nbits, n, key, m):
    m_hash = hashlib.sha256(m.encode())
    hash_int = int.from_bytes(m_hash.digest(), sys.byteorder)
    m_enc = pow(hash_int, key, n)
    return m_enc


def writeOut(name, m):
    with open(name, "w") as f:
        f.write(str(m))

if __name__ == "__main__":
    args = signIO.parse()
    signIO.parseInput(args)
    m = signIO.getInput(args)
    nbits, n, key = signIO.getKey(args)

    m_enc = sign(int(nbits), int(n), int(key), m)

    writeOut(args.sig_file, m_enc)
