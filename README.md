# NullCrypt
Text Encryption and Decryption Tool that encrypts text using different algorithms like AES, DES and RSA for secure data protection.

✅ Features:
Enter text

Choose algorithm: AES, DES, RSA

Choose Encrypt or Decrypt

Enter key (manual input or load from file for RSA)

View the output



📦 Requirements:

Install pycryptodome  : pip install pycryptodome


🛠 How to Run:

python3 text_encryption.py


🔐 Notes:

AES key must be exactly 16 characters

DES key must be 8 characters

RSA requires loading .pem public/private key files


Additional info:

Why You Need to Choose a File When Encrypting with RSA:
In RSA encryption, you need to use a public key for encryption and a private key for decryption. When you're encrypting text using RSA, you need to provide the public key to the tool.

Public Key: This is the key used for encryption. It's meant to be shared with anyone who wants to send you encrypted messages. The public key is typically stored in a file (usually with a .pem or .pub extension) that contains the key's information.

The tool you are using requires you to select the public key file because:

Public keys are often stored in files: Instead of typing in a public key directly, it is more common and practical to store it in a file (especially if the key is large) and then load it into the tool.

Key format: The RSA public key is usually stored in a specific format, such as PEM, DER, or in some cases, a .pub file. These formats include both the key and the metadata required for the encryption process.

Types of Files You Should Use:
1.PEM (.pem):

This is the most common format for RSA keys. The PEM format is a Base64-encoded representation of the public key enclosed between -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----. This file can be generated using tools like OpenSSL.

Example of a PEM file:

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7C9GdoLeu5pT4wmXHftC
...
-----END PUBLIC KEY-----


2.PUB (.pub):

The .pub extension is often used for SSH public keys, but it can also contain an RSA public key in a similar format to PEM. Some tools may generate keys in .pub format for ease of use, especially when working with SSH or other services.

3.DER (.der):

This is a binary format for storing keys. Unlike PEM, it is not Base64-encoded, and you may need to convert it to PEM format before using it with some tools.

How to Generate an RSA Public Key File:
You can generate an RSA public key using tools like OpenSSL or ssh-keygen (for SSH keys). Here's an example of generating a public key with OpenSSL:

Generate a Private Key:  openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
Generate the Corresponding Public Key:  openssl rsa -pubout -in private_key.pem -out public_key.pem

This will create a public_key.pem file that you can use for the encryption in your tool.




