#!/usr/bin/python3
'''
Karnauch, Andrey
CS483 - unlock.py
Unlocks a directory that was locked via lock.py
'''
from cs483 import lockIO
import rsa_dec
import rsa_sign
import binascii
import sys
import os
import subprocess
import shlex

#same as lock.py
def getInput(a_pubk):
    with open(a_pubk, "r") as f:
        three_lines = f.read()

        split = three_lines.splitlines()
        nbits = split[0]
        n = split[1]
        key = split[2]
        return int(nbits), int(n), int(key)

#same as lock.py
def validateKey(key, msg, casig):
    key = "-k " + key
    msg = " -m " + msg
    casig = " -s " + casig
    args = shlex.split("source/rsa_validate.py "+key+msg+casig)
    res = subprocess.run(args, stdout=subprocess.PIPE)
    if (res.stdout == b'False\n'):
        print("Locking party's public key CANNOT be verified, aborting", file=sys.stderr)
        exit(1)

'''
gets the two AES keys out of the manifest file
decrypts the two keys using the private RSA key
writes keys to temp file for decryption
'''
def getKeys(args):
    name = os.path.join(args.directory, "key-manifest")
    nbits, n, key = getInput(args.a_privk)
    with open (name, "r") as f:
        keys = f.read()

    split = keys.splitlines()
    enc_aes_key = split[0]
    tag_aes_key = split[1]

    enc_key = rsa_dec.dec(nbits, n, key, int(enc_aes_key))
    tag_key = rsa_dec.dec(nbits, n, key, int(tag_aes_key))
    
    enc_key = enc_key.to_bytes(32, sys.byteorder)
    tag_key = tag_key.to_bytes(32, sys.byteorder)

    with open("temp-enc", "w") as f:
        f.write(binascii.hexlify(bytearray(enc_key)).decode("utf-8"))
    with open("temp-tag", "w") as f:
        f.write(binascii.hexlify(bytearray(tag_key)).decode("utf-8"))

'''
verifies the key-manifest files using the signature provided
@return: exits if not verified
'''
def validateManifest(key, args):
    name = os.path.join(args.directory, "key-manifest")
    namesig = os.path.join(args.directory, "sig-key-manifest")

    key = "-k " + key
    msg = " -m " + name
    sig = " -s " + namesig
    arg = shlex.split("source/rsa_validate.py "+key+msg+sig)
    res = subprocess.run(arg, stdout=subprocess.PIPE)
    if (res.stdout == b'False\n'):
        print("Locking party's signature CANNOT be verified, aborting", file=sys.stderr)
        exit(1)

    getKeys(args)

'''
goes through each tag file in a directory and validates them
removes the tag files if they validate
removes the temp file storing the AES key
@return: exits if one file does not validate
'''
def validateTags(args):
    key = "-k temp-tag"
    for f in os.listdir(args.directory):
        if f.endswith("-tag"):
            name = os.path.join(args.directory, f)
            msg = " -m " + name[:-4] + "-enc"
            tag = " -t " + name
            arg = shlex.split("source/cbcmac_validate.py "+key+msg+tag)
            res = subprocess.run(arg, stdout=subprocess.PIPE)
            if (res.stdout == b'True\n'):
                os.remove(name)
            else:
                os.remove("temp-tag")
                print("Tag for '{}' can't be verified, aborting".format(name[:-4]), file=sys.stderr)
                exit(1)

    os.remove("temp-tag")

'''
goes through each encrypted file in dir and decrypts
removes the enc files if they validate
removes the temp file storing the AES key
'''
def decFiles(args):
    key = "-k temp-enc"
    for f in os.listdir(args.directory):
        if f.endswith("-enc"):
            name = os.path.join(args.directory, f)
            input_file = " -i " + name
            out_file = " -o " + name[:-4]
            arg = shlex.split("source/cbc_dec.py "+key+input_file+out_file)
            res = subprocess.run(arg)
            os.remove(name)

    os.remove(os.path.join(args.directory, "key-manifest"))
    os.remove(os.path.join(args.directory, "sig-key-manifest"))
    os.remove("temp-enc")

if __name__ == '__main__':
    args = lockIO.parse()
    lockIO.parseInput(args)

    val_key = args.validating
    a_pubk = args.a_pubk
    casig = a_pubk + "-casig"
    validateKey(val_key,a_pubk,casig)
    validateManifest(a_pubk, args)
    validateTags(args)
    decFiles(args)
