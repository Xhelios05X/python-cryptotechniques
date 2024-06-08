#!/bin/python3

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import argparse
import sys

import rsa 

# ToDo
# - add description


def Help():
    parser = argparse.ArgumentParser(
        prog = "CurrencyExchangeRate.py",
        description = "ToDo",
    )

    parser.add_argument("--aes", action = "store_true")
    parser.add_argument("--dsignature", action = "store_true")
    parser.add_argument("filename")
    parser.add_argument("password",
                        nargs = "?",
                        help = "optional argument to the AES encription")

    args = parser.parse_args()
    return args

def RSAkeys():
    (pubkey, privkey) = rsa.newkeys(2048)
    return (pubkey, privkey,)

def DigitalSignature(filename: str):
    
    # it's tuple
    # rsaKeys[0] - public key
    # rsaKeys[1] - private key
    rsaKeys = RSAkeys()

    # opening file
    file = open(filename, "rb")
    fileData = file.read()
    file.close()

    # creating a hash and encrypting it with RSA private key
    signature = rsa.sign(fileData, rsaKeys[1], "SHA-256")

    # saving a digital signature to the file
    file = open(f"{filename}_signature", "wb")
    file.write(signature)
    file.close()
    print(f"It's your public key:\n {rsaKeys[0]}")

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
if __name__ == "__main__":
    help = Help()

    filename = help.filename
    password = help.password

    if help.aes:
        if type(password) == "NoneType":
            sys.exit(-1)

        try:
            with open(filename, "r") as f:
                stringToEncode = f.read()
        
            encriptionAES(stringToEncode, password)
        except:
            sys.exit(-1)

    elif help.dsignature:
        DigitalSignature(filename)

    elif not help.dsignature and not help.aes:
        print("You have to choose one of the options")
        sys.exit(-1)