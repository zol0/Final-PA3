#!/usr/bin/python3.5
'''
Karnauch, Andrey
CS483 - rsa_dec.py
Decrypt a base10 integer that was encrypted using RSA PKCS1.5
'''
from cs483 import rsaIO
import sys

'''
Decrypts a base10 integer by stripping padding and performing m^d
@param n, nbits: the public key N and its bit size
@param key: the inverse multiplicative mod of the public key e
@param m: the base10 integer to decrypt
@return: the base10 integer representing a message
'''
def dec(nbits, n, key, m):
    m_inv = pow(m, key, n)
    m_dec = m_inv.to_bytes(m_inv.bit_length()//8+1, sys.byteorder)

    strip_amount = 3 + (nbits//2//8)
    m_stripped = m_dec[strip_amount:]
    m_stripped = m_stripped.lstrip(b'\x00')
    m_plain = int.from_bytes(m_stripped, sys.byteorder)
    return m_plain

#Processes input, decrypts message, and prints decrypted message to file
if __name__ == "__main__":
    args = rsaIO.parse()
    rsaIO.parseInput(args)
    m = rsaIO.getInput(args)
    nbits, n, key = rsaIO.getKey(args)

    m_dec = dec(int(nbits), int(n), int(key), int(m))

    with open(rsaIO.args.output_file, "w") as w:
        w.write(str(m_dec))

