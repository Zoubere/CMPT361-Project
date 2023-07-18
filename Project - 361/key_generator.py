from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generates private and public keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

userName = input("Enter your username: ").strip()

with open(userName + "_public.pem", "wb") as file:
    file.write(public_key)


with open(userName + "_private.pem", "wb") as file:
    file.write(private_key)