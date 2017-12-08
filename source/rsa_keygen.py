#!/usr/bin/python3.5
'''
Karnauch, Andrey
CS483 - rsa_keygen.py
Generates a public/private key pair for RSA and signs it
'''
from cs483 import kgIO
from Crypto.Util import number
from math import gcd
import rsa_sign
import math

'''
Obtains the multiplicative modular inverse of e mod phi
Uses Extended Euclidean Algorithm - referenced from:
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
@param e: the number we are trying to find the inverse for
@param phi: the order of our group, also our modulus
@return: a number x such that e*x mod phi = 1 mod phi
        this number serves as our private key for RSA
'''
def modInv(e, phi):
    lastx, y = 1, 1
    lasty, x = 0, 0
    orderN = phi

    while phi:
        q = e // phi
        x, lastx = lastx - q*x, x
        y, lasty = lasty - q*y, y
        e, phi = phi, e % phi

    return lastx % orderN

'''
Find part of the public key for RSA
Obtains a value e such that e is small and coprime with the order of the group
@param orderN: order of the group - (p-1)(q-1)
@return: a number coprime to the order of the group
'''
def genE(orderN):
    for e in range(3, orderN, 2):
        if (gcd(e, orderN) == 1):
            return e

'''
Generates a public/private key pair for RSA
@param bits: The desired BIT size of N where N = pq and p,q are large primes
@return: The obtained N, public key used for encryption e, and private key d for decryption
'''
def genKeys(bits):
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    N = p*q
    while (N.bit_length() != bits):
        q = number.getPrime(bits // 2 + 1)
        N = p*q
    
    orderN = (p-1)*(q-1)
    e = genE(orderN)
    d = modInv(e, orderN)

    return N, e, d

def writeFile(name, N, key):
    with open(name, "w") as w:
        w.write(str(N.bit_length()) + "\n")
        w.write(str(N) + "\n")
        w.write(str(key) + "\n")

if __name__ == "__main__":
    bits = int(kgIO.args.num_bits)
    nbits, n, ca_key = kgIO.getCA()

    N, e, d = genKeys(bits)
    pub_key = str(N.bit_length()) + "\n"
    pub_key += str(N) + "\n"
    pub_key += str(e) + "\n"

    if (ca_key == None): signed = rsa_sign.sign(bits, N, d, pub_key)
    else: signed = rsa_sign.sign(int(nbits), int(n), int(ca_key), pub_key)

    writeFile(kgIO.args.public_key, N, e)
    writeFile(kgIO.args.private_key, N, d)
    sig_file = kgIO.args.public_key + "-casig"
    with open(sig_file, "w") as f:
        f.write(str(signed))
