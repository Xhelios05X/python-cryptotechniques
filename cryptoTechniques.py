#!/bin/python3

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import argparse
import sys

# ToDo
# - add description
# - add argument 1
# - add argument 2


def Help():
    parser = argparse.ArgumentParser(
        prog = "CurrencyExchangeRate.py",
        description = "ToDo",
    )

    parser.add_argument("--aes", action = "store_true")
    parser.add_argument("filename")
    parser.add_argument("password")
    # Todo: add arguments

    args = parser.parse_args()
    return args


def encriptionAES(stringToEncode:str, password:str):
    salt = "b'\x13\x85Q[W\xc8\x12Y \x81\xec\xb0%)\x15\xb5'"

    # genarates key to encode message
    key = PBKDF2(password, salt, dkLen=32)

    # make an AES object
    cipher = AES.new(key, AES.MODE_CBC)

    # makes a ciphered data based on cipher object
    ciphered_data = cipher.encrypt(pad(stringToEncode, AES.block_size))

    with open("encyptedFile.bin", "wb") as f:
        f.write(cipher.iv)
        f.write(ciphered_data)



# main function
# sys.argv[1] - filename
# sys.argv[2] - password
if __name__ == "__main__":
    help = Help()

    filename = sys.argv[1]
    password = sys.argv[2]

    if help.aes:
        with open(filename, "r") as f:
            stringToEncode = f.read()
        
        encriptionAES(stringToEncode, password)
    