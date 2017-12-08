#!/usr/bin/python3
'''
Karnauch, Andrey
CS483 - rsa_enc.py
Encrypts an element (base10 integer) in Z*_n using RSA PKCS1.5
'''
from cs483 import rsaIO
import random
import sys
import os

'''
Generates random non-zero bits for padding in RSA PKCS1.5
@param r: an integer indicating the number of padding BITS needed
@return: a byte string consisting of the BYTE amount requested
'''
def genRandom(r):
    rbytes = r // 8
    padr = b''
    while (len(padr) < rbytes):
        num_zeros = rbytes - len(padr)
        get_bytes = os.urandom(num_zeros)
        get_bytes = get_bytes.replace(b'\x00', b'')
        padr = padr + get_bytes

    return padr

'''
Pads the message before encryption using PKCS1.5 standards
@param n, nbits: the public key N and its bit size
@param m: the plain base10 integer message to encrypt
@return: a byte string ready to be encrypted using RSA PKCS1.5
NOTE: some bits may be lost during the process, but byte length is retained
'''
def pad(m, nbits, n):
    r = nbits // 2
    max_length = r - 24

    rbytes = r // 8
    mbytes = m.bit_length() // 8

    left_over = r - (rbytes*8)
    if (m.bit_length() > max_length): 
        print('**ERROR**\n',
        'Bits in N = %d\n' % nbits,
        'Bits in R = %d\n' % r,
        'Bits in message = %d\n' % m.bit_length(),
        'Total = %d + %d + 24 = %d\n'
        % (r, m.bit_length(), 24+r+m.bit_length()),
        'Message too large!')
        exit(1)

    need = max_length - m.bit_length() + left_over
    num_zeros = need // 8

    zero_string = bytearray(num_zeros)

    padding = genRandom(r)
    return b'\x00' + b'\x02' + padding + b'\x00'+ zero_string + m.to_bytes(mbytes+1, sys.byteorder)

'''
Encrypts an element (base10 integer) in Z*_n using RSA PKCS1.5
@param n, nbits: the public key N and its bit size
@param m, key: the base10 int to be encrypted and the public key e
@return: the m with appropriate padding, raised to the e -- m^e
'''
def enc(nbits, n, key, m):
    rv = pad(m, nbits, n)
    m_int = int.from_bytes(rv, sys.byteorder)
    m_enc = pow(m_int, key, n)
    return m_enc


if __name__ == "__main__":
    args = rsaIO.parse()
    rsaIO.parseInput(args)
    m = rsaIO.getInput(args)
    nbits, n, key = rsaIO.getKey(args)

    m_enc = enc(int(nbits), int(n), int(key), int(m))

    with open(rsaIO.args.output_file, "w") as w:
        w.write(str(m_enc))
