'''
Karnauch, Andrey
CS483 - IO module
Processes input arguments using argparse
'''

import sys
import binascii
import argparse

parser = argparse.ArgumentParser(description='Encrypt and/or decrypt some files')
parser.add_argument("-k", dest="key_file",help="File storing valid AES key as a hex encoded string")
parser.add_argument("-m", dest="msg_file",help="File that is being operated on")
parser.add_argument("-t", dest="tag_file",help="File where resulting output is stored")
parser.add_argument("-v", dest="optional_IV_file",help="File storing valid IV as hex encoded string")

args = parser.parse_args()

if (args.key_file == None):
    print("Must include a key file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.msg_file == None):
    print("Must include a message file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.tag_file == None):
    print("Must include a tag file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()

'''
Reads key in from the file provided via command line arguments
@return: returns the hex encoded string as a byte string
'''
def getKey():
    with open(args.key_file, "rb") as k:
        key = k.read()
        key = binascii.unhexlify(key)
        return key

'''
Reads input in from the file provided via command line arguments
@return: returns the byte string
'''
def getInput():
    with open(args.msg_file, "rb") as f:
        s = f.read()
        return s

def getTag():
    with open(args.tag_file, "rb") as f:
        s = f.read()
        return s
'''
Reads IV in from the file provided via command line arguments
@return: returns the hex encoded string as a byte string
@return: if no IV file provided, returns None
'''
def getIV():
    if (args.optional_IV_file != None):
        with open(args.optional_IV_file, "rb") as f:
            iv = f.read()
            iv = binascii.unhexlify(iv)
            return iv
    else: return None
