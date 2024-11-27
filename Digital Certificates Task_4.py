import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

#load the public key
public_key = RSA.import_key(open('public.pem').read())

#load the private key | need it to sign the unsigned message to compare
#the generated signature
private_key = RSA.import_key(open('private.key').read())

#Load original Message
with open('unsigned_message.txt', 'r') as f:
    unsigned_message = f.read()

#Hash the message
hash = SHA256.new(unsigned_message.encode())

#import signature
with open("signature.sig", "rb") as f:
    signature = f.read()


#---------VERIFY AUTHENTICITY OF SIGNATURE USING PUBLIC KEY
try: 
    pkcs1_15.new(public_key).verify(hash, signature)
    print("Signature is valid")
except (ValueError, TypeError):
    print("Signature is invalid")



