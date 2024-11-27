from Crypto.PublicKey import RSA
#Purpose: Imports the RSA functionality from pycryptodome. RSA is an asymmetric cryptographic algorithm used for encryption, decryption, and signing.
#Why needed? You need this to generate a private key, which is essential for signing the message.

from cryptography.hazmat.primitives import serialization


from Crypto.Hash import SHA256
#Purpose: Imports the SHA-256 hash algorithm for hashing data.
#Why needed? Cryptographic signatures require a message digest (hash) to ensure the integrity of the data being signed. 
# SHA-256 is a secure, widely-used hashing algorithm.


from Crypto.Signature import pkcs1_15 #signature scheme based on RSA
#Why needed? This is the specific signature scheme you are using to sign the hashed message.


import base64
#Purpose: Imports the base64 module to encode binary data into a readable format.
#Why needed? Signature outputs are in binary form, which is not user-friendly. Base64 encoding makes it readable and transferable.


#Generate the private key
private_key = RSA.generate(2048)

#Save the Private Key to a file
with open('private.key', 'wb') as f:
    f.write(
        private_key.export_key(format='PEM')
    )


#Generate the public key and save to file
with open('public.pem', 'wb') as f:
    f.write(
        private_key.public_key().export_key(format='PEM')
    )



#The message we want to sign
message = input('Enter the message you want to sign using the private key\n')

with open('unsigned_message.txt', 'w') as f:
    f.write(message)

hash = SHA256.new(message.encode())
#Purpose: Hashes the input message using SHA-256.
#Why encode? The message input is a string, but the hashing function requires binary data. encode() converts the string to bytes.
#Why hash the message? RSA signing is computationally expensive and works with fixed-size inputs. Hashing the message ensures:

#    The input size is manageable.
#    Integrity: Any change in the message alters the hash.


signature = pkcs1_15.new(private_key).sign(hash)
#Purpose: Creates a digital signature for the hashed message using the private RSA key.
#Why sign the hash?

#    RSA cannot directly sign large or arbitrary-length messages.
 #   Signing the hash ensures a fixed-size input for the cryptographic operation.
  #  This provides a way to verify both the origin and integrity of the message.
  #This means we dont need to manually do cryptographic padding because the message signature is a fixed input size for the cyrptographic operation



#Save the Signature formatted in Base64 to a file
with open('signature.sig', 'wb') as f:
    f.write(signature)



result = base64.b64encode(signature).decode()
#Purpose: Encodes the binary signature into a Base64 string for readability and transfer.
#Why Base64? Binary signatures may contain non-printable characters, making them difficult to display or send via text-based protocols. 
#Base64 converts the binary data into a text format.


#Print the signature in base64 readable format
print('\n',result)



