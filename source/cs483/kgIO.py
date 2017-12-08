'''
Karnauch, Andrey
CS483 - IO module
Processes input arguments using argparse for rsa_keygen.py
'''

import sys
import binascii
import argparse

parser = argparse.ArgumentParser(description='Generate an RSA key')
parser.add_argument("-p", dest="public_key",help="File to store public key")
parser.add_argument("-s", dest="private_key",help="File to store private key")
parser.add_argument("-n", dest="num_bits",help="Specifies number of bits in your N")
parser.add_argument("-c", dest="ca_key",help="File storing CA's private key")

args = parser.parse_args()

if (args.public_key == None):
    print("Must output a public key file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.private_key == None):
    print("Must output a private key file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.num_bits == None):
    print("Must specify number of bits in N", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()

def getCA():
    if (args.ca_key != None):
        with open(args.ca_key, "r") as f:
            three_lines = f.read()

        split = three_lines.splitlines()
        nbits = split[0]
        n = split[1]
        key = split[2]
        return nbits, n, key

    else: return None, None, None
