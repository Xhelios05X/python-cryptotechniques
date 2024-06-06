#!/bin/python3

from Crypto.Protocol.KDF import PBKDF2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encriptionAES(stringToEncode:str, password:str):
    salt = "b'\x13\x85Q[W\xc8\x12Y \x81\xec\xb0%)\x15\xb5'"

    # genarates key to encode message
    key = PBKDF2(password, salt, dkLen=32)

    # make an AES object
    cipher = AES.new(key, AES.MODE_CBC)

    # makes a ciphered data based on cipher object
    ciphered_data = cipher.encrypt(pad(stringToEncode, AES.block_size))

if __name__ == "__main__":
    pass