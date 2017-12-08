#!/usr/bin/python3
'''
Karnauch, Andrey
CS483 - lock.py
Locks a directory
'''
from cs483 import lockIO
import rsa_enc
import rsa_sign
import binascii
import sys
import os
import subprocess
import shlex

'''
reads in a given key in the format of PA2
@a_pubk: filename
@return: nbits, n, key in that file
'''
def getInput(a_pubk):
    with open(a_pubk, "r") as f:
        three_lines = f.read()

        split = three_lines.splitlines()
        nbits = split[0]
        n = split[1]
        key = split[2]
        return int(nbits), int(n), int(key)

'''
calls rsa_validate to validate a signed key
@key,msg,casig: all files to use for rsa_validate
@return: exits if it does not validate
'''
def validateKey(key, msg, casig):
    key = "-k " + key
    msg = " -m " + msg
    casig = " -s " + casig
    args = shlex.split("./rsa_validate.py "+key+msg+casig)
    res = subprocess.run(args, stdout=subprocess.PIPE)
    if (res.stdout == b'False\n'):
        print("Unlocking party's public key CANNOT be verified, aborting", file=sys.stderr)
        exit(1)

'''
signs a set of keys - one for AES enc, one for tagging
@msg: message consisting of both keys, separated by newline
'''
def signKeys(msg, args):
    a_privk = args.a_privk
    nbits, n, key = getInput(a_privk)
    result = rsa_sign.sign(nbits, n, key, msg)
    name = os.path.join(args.directory, "sig-key-manifest")
    rsa_sign.writeOut(name, result)

'''
generates two keys and puts them into manifest (encrypted via RSA)
also create two temp files storing actual keys for encryption/tagging
calls signKeys to generate signature for manifest 
'''
def genKeys(args):
    a_pubk = args.a_pubk
    aes_enc_key = os.urandom(32)
    aes_tag_key = os.urandom(32)
    nbits, n, key = getInput(a_pubk)
    enc_key = rsa_enc.enc(nbits, n, key, int.from_bytes(aes_enc_key, sys.byteorder))
    enc_key2 = rsa_enc.enc(nbits, n, key, int.from_bytes(aes_tag_key, sys.byteorder))
    msg = str(enc_key) + "\n" + str(enc_key2)

    name = os.path.join(args.directory, "key-manifest")

    with open("temp-enc", "w") as f:
        f.write(binascii.hexlify(bytearray(aes_enc_key)).decode("utf-8"))
    with open("temp-tag", "w") as f:
        f.write(binascii.hexlify(bytearray(aes_tag_key)).decode("utf-8"))
    with open(name, "w") as f:
        f.write(msg)

    signKeys(msg, args)

'''
encrypts all files in a given directory using CBC mode
removes the temporary key file storing the AES key used
'''
def encFiles(args):
    directory = args.directory
    key = "-k temp-enc"
    for f in os.listdir(directory):
        if f.endswith("key-manifest"):
            pass
        else:
            name = os.path.join(directory, f)
            input_file = " -i " + name
            out_file = " -o " + name + "-enc"
            arg = key + input_file + out_file
            arg = shlex.split("./cbc_enc.py " + arg)
            res = subprocess.run(arg)
            os.remove(name)

    os.remove("temp-enc")

'''
tags all the encrypted files in a given directory
removes the temporary tag key file
'''
def tagFiles(args):
    directory = args.directory
    key = "-k temp-tag"
    for f in os.listdir(directory):
        if f.endswith("-enc"):
            name = os.path.join(directory, f)
            msg_file = " -m " + name
            new_name = name[:-4] + "-tag"
            tag_file = " -t " + new_name
            arg = key + msg_file + tag_file
            arg = shlex.split("./cbcmac_tag.py " + arg)
            res = subprocess.run(arg)

    os.remove("temp-tag")

if __name__ == '__main__':
    args = lockIO.parse()
    lockIO.parseInput(args)

    val_key = args.validating
    a_pubk = args.a_pubk
    casig = a_pubk + "-casig"
    validateKey(val_key,a_pubk,casig)
    genKeys(args)
    encFiles(args)
    tagFiles(args)
