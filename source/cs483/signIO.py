'''
Karnauch, Andrey
CS483 - IO module
Processes input arguments using argparse for rsa_enc.py and rsa_dec.py
'''

import sys
import binascii
import argparse

def parseInput(args):
    if (args.key_file == None):
        print("Must include a key file", file=sys.stderr)
        print("Rerun using '-h' for help", file=sys.stderr)
        sys.exit()
    elif (args.msg_file == None):
        print("Must include a message file", file=sys.stderr)
        print("Rerun using '-h' for help", file=sys.stderr)
        sys.exit()
    elif (args.sig_file == None):
        print("Must include a signature file", file=sys.stderr)
        print("Rerun using '-h' for help", file=sys.stderr)
        sys.exit()

def getKey(args):
    if (args.key_file != None):
        with open(args.key_file, "r") as f:
            three_lines = f.read()

        split = three_lines.splitlines()
        nbits = split[0]
        n = split[1]
        key = split[2]
        return nbits, n, key

    else: return None

def getSig(args):
    with open(args.sig_file, "r") as f:
        s = f.read()
        return s

def getInput(args):
    with open(args.msg_file, "r") as f:
        s = f.read()
        return s

def parse():
    parser = argparse.ArgumentParser(description='Encrypt/Decrypt an RSA integer')
    parser.add_argument("-k", dest="key_file",help="Key file generated using rsa-gen") 
    parser.add_argument("-m", dest="msg_file",help="Message to hash using SHA256")
    parser.add_argument("-s", dest="sig_file",help="Output file for rsa-sign, input for rsa-validate")
    args = parser.parse_args()
    return args
