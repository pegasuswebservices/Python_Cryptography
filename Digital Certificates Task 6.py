import base64
import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.serialization
from cryptography.hazmat.primitives import hashes
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
#import fernet as need to use for symmetric encryption
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from Crypto.Hash import SHA256



#--Key Generation: Create ASYMMETRIC Encryption Keys--------

#--Create PrivateKey and save to file
t6_private_key = RSA.generate(2048)
with open("t6_private.key", "wb") as f:
    f.write(
        t6_private_key.export_key(format="PEM")
    )
t6_public_key = t6_private_key.public_key()
#-- Create Public Key and save to file
with open ("t6_public.pem", "wb") as f:
    f.write(
       t6_public_key.export_key(format="PEM")
    )



#---Key Generation: Create SYMMETRIC Encryption Keys----------

symmetric_key = Fernet.generate_key()

#Creating the cipher with the recpient's public key
public_key_cipher = PKCS1_OAEP.new(t6_public_key)

#encrypting the Symmetric key with the cipher
encyrpted_sym_key = public_key_cipher.encrypt(symmetric_key)



print(f'Encrypted Symmetric key is: {encyrpted_sym_key}')



#-------ENCRYPT THE MESSAGE-----------------------------------
#Use the Encrypted Symmetric Key to encrypt the Message.
message = input("Enter the message to encrypt:\n\n")

#--Derive a symmetric cipher from the encrypted symmetric key
#Hash the encrypted symmetric key to derive a cipher from it
derived_key = sha256(encyrpted_sym_key).digest()[:32] #fernet expects 32byte key

symmetric_cipher_from_enc_sym = Fernet(base64.urlsafe_b64encode(derived_key))


#Noew Use the Encrypted Symmetric key cipher to encrypt the message

encrypted_message = symmetric_cipher_from_enc_sym.encrypt(message.encode())

print(f"Encrypted Message: {encrypted_message.decode()}")



#Now decrypt the message
decrypted_message = symmetric_cipher_from_enc_sym.decrypt(encrypted_message)


#.decode() so gets ride of the bytes bit at start of string.
print(f"Decrypted Message: {decrypted_message.decode()}")



#----Now decrypt the symmetric key itself using the private key
#Create Private Key Cipher
private_key_cipher = PKCS1_OAEP.new(t6_private_key)

#Decrpyt using private key cipher
decrypted_sym_key = private_key_cipher.decrypt(encyrpted_sym_key)


print(f"Decrypted Symmetric Key: {decrypted_sym_key.decode()}")





#--------ADD SIGNATURE TO THE MESSAGE USING SENDERS PRIVATE KEY----------------

#1) Hash Message
hash = SHA256.new(encrypted_message)

#2) Sign Using Private Key
signature = pkcs1_15.new(t6_private_key).sign(hash)



#--------VERIFY MESSAGE USING RECIPIENT'S PUBLIC KEY--------

try:
    pkcs1_15.new(t6_public_key).verify(hash, signature)
    print("Signature is valid. Message integrity is intact")
except(ValueError, TypeError):
    print("Signature is invalid. Message has been tampered with.")