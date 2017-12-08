'''
Karnauch, Andrey
CS483 - AESHelper module
AESHelper class deals with the AES ECB processing
'''

import binascii, sys
from Crypto import Random
from Crypto.Cipher import AES

BSIZE = AES.block_size

class AESHelper:
    
    '''Initialize the object with a key
    '''
    def __init__(self,key):
        self.key = key

    '''
    Takes in raw text and runs it through the AES encryption
    @param text: string of bytes
    @return: string of encrypted text
    '''
    def encrypt(self,text):
        cipher = AES.new(self.key,1)
        return cipher.encrypt(text)

    '''Same as encrypt() except it calls AES decrypt()
    '''
    def decrypt(self,text):
        cipher = AES.new(self.key,1)
        return cipher.decrypt(text)

    '''
    Converts two byte strings into ints, XORs them, then returns resulting string
    Ensures only length of message is XORed (prevents padding in CTR mode)
    @param text, iv: string of bytes
    @return: the byte string after XORing the integer representation of both strings
    '''
    def xor(self, text, iv):
        iv = iv[:len(text)]
        iv_int = int.from_bytes(iv, sys.byteorder)
        plain_int = int.from_bytes(text, sys.byteorder)
        xor_int = plain_int ^ iv_int
        return xor_int.to_bytes(len(text), sys.byteorder)

    '''
    Chops off extra bytes of padding in CBC mode
    @param msg: the DECRYPTED message of cbc-dec
    @return: the DECRYPTED message with no extra padding bytes
    '''
    def unpad(self, msg):
        num_bytes = msg[-1]
        return msg[:len(msg)-num_bytes]

    '''
    Pads the message before CBC encryption using PKCS#7
    @param msg: the PLAINTEXT byte string prior to CBC encryption
    @return: the same byte string but with appended padding bytes
    '''
    def pad(self, msg):
        need = BSIZE - (len(msg) % BSIZE)
        msg += bytes([need])*need
        return msg
