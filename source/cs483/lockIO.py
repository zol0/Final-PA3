import sys
import binascii
import argparse

def parseInput(args):
    if (args.directory == None):
        print("Must include a directory to lock/unlock", file=sys.stderr)
        sys.exit()
    elif (args.a_pubk == None):
        print("Must include an action public key", file=sys.stderr)
        sys.exit()
    elif (args.a_privk == None):
        print("Must include an aciton private key", file=sys.stderr)
        sys.exit()
    elif (args.validating == None):
        print("Must include a validating public key", file=sys.stderr)
        sys.exit()

def parse():
    parser = argparse.ArgumentParser(description='Lock a directory of files')
    parser.add_argument("-d", dest="directory")
    parser.add_argument("-p", dest="a_pubk")
    parser.add_argument("-r", dest="a_privk")
    parser.add_argument("-vk", dest="validating")
    args = parser.parse_args()
    return args
