import base64

import rsa

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES, PKCS1_OAEP

def generate_keys(pubKeyFile, privKeyFile):
    # Use a breakpoint in the code line below to debug your script.
    (pubKey, privKey) = rsa.newkeys(2048)
    with open('pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))
    with open('privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))


def load_keys(pubKeyFile, privKeyFile):
    with open(pubKeyFile, 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())
    with open(privKeyFile, 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())
    return pubKey, privKey


def encrypt(plaintext, key):
    return rsa.encrypt(plaintext.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except():
        return False


def sign_sha256(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-256')


def verify_sha256(plaintext, signature, key):
    try:
        return rsa.verify(plaintext.encode('ascii'), signature, key) == 'SHA-256'
    except():
        return False


def encrypt_file_with_aes(textfile, ciphertextfile):
    """
    The following code generates a new AES256 key and encrypts textfile into ciphertextfile.
    We use the EAX mode because it allows the receiver to detect any unauthorized modification (similarly,
    we could have used other authenticated encryption modes like GCM, CCM or SIV).
    """
    # Reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    key = get_random_bytes(32)  # 32 bytes = 256 bits
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(textfile)
    with open(ciphertextfile, "wb") as file_out:
        [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    return key


def decrypt_file_with_aes(ciphertexfile, key):
    with open(ciphertexfile, "rb") as file_in:
        nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return False


def main():
    # Key filename
    pubKeyFile = "pubkey.pem"
    privKeyFile = "privkey.pem"

    # Uncomment the next line to generate a new RSA public/private key pair
    # generate_keys(pubKeyFile, privKeyFile)

    # Load the public and private key pair from the files
    pubKey, privKey = load_keys(pubKeyFile, privKeyFile)

    """
    Example of a message encryption and decryption, then signing and verifying.
    """
    # START A
    # Some message in plaintext
    original_message = "Plaintext Message"

    # Sender encrypts the message with the recipient's public key. In this case, only the recipient can decrypt the
    # ciphertext with his/her private key (Confidentiality):
    ciphertext = encrypt(original_message, pubKey)
    # Decrypt with the private key (Recipient):
    plaintext = decrypt(ciphertext, privKey)
    # Verify that the decryption worked:
    if plaintext:
        print(f'The plaintext is {plaintext}')
    else:
        print(f'Failed to decrypt')

    # Sender signs the message with its private key and the recipient verifies it with the sender's public key.
    signature = sign_sha256(original_message, privKey)
    # Recipient verifies the signature
    if verify_sha256(plaintext, signature, pubKey):
        print(f'Signature verified')
    else:
        print(f'Failed to verify')
    # END B

    """
    # Source: 5.4. Working with big files
    # https://stuvel.eu/python-rsa-doc/usage.html#encryption-and-decryption

    # RSA cannot encrypt a file larger than the key (minus some random padding) A 512 bit (64 bytes) RSA key can be used 
    to encrypt a 63 byte file. The most common way to use RSA with larger files uses a block cypher like AES or DES3 to 
    encrypt the file with a random key, then encrypt the random key with RSA.You would send the encrypted file along 
    with the encrypted key to the recipient.The complete flow is:

    1. Create a 256 bit AES key
    2. Encrypt the large file using the aes key (symmetric encryption)
    3. Encrypt the aes key using RSA with the recipient's public key (asymmetric encryption)
    4. Sign the large file using RSA with the sender's private key
    5. Send (or save) the signature, encrypted AES key, and ciphertext
    5. Recipient decrypts the encrypted AES key with the recipient's private key.
    6. Recipient decrypts the large file with the obtained plaintext AES key.
    7. Recipients verifies the signature with the plaintext large file and the sender's public key.
    """

    # Read a Big File (bigFile.pdf) and save it to the variable bigFile
    with open('bigFile.pdf', 'rb') as file:
        bigFile = file.read()

    # Call the file encryption method and save the return value as the AES key
    aes_key = encrypt_file_with_aes(bigFile, 'bigFile.bin')
    print(f'A Original AES key            = {aes_key} with type {type(aes_key)}')

    # Convert the AES key from bytes to str
    encoded_aes_key = base64.b64encode(aes_key).decode()
    print(f'A2 Encoded key                = {encoded_aes_key} with type {type(encoded_aes_key)}')

    # Encrypt the converted AES key with the recipient's public RSA key (now only the private RSA key can decrypt it)
    encrypted_aes_key = encrypt(encoded_aes_key, pubKey)
    print(f'B Original encrypted AES key  = {encrypted_aes_key} with type {type(encrypted_aes_key)} ')

    # Save the encrypted AES key to a file
    with open('encrypted_aes_key.bin', 'wb') as aes_file:
        aes_file.write(encrypted_aes_key)

    # Create the signature with the sender's private key
    bigFileSignature = sign_sha256(base64.b64encode(bigFile).decode(), privKey)
    print(bigFileSignature)

    # Write the signature to signature.bin
    with open('signature.bin', 'wb') as f:
        f.write(bigFileSignature)

    # Jeopardy Music...send encrypted file, encrypted AES key and signature
    # In our case the sender saved them to files and the recipient will read them from those files

    # Read the encrypted AES key from a file
    with open('encrypted_aes_key.bin', 'rb') as aes_file:
        loaded_encrypted_aes_key = aes_file.read()
    print(f'C Loaded encrypted AES key    = {loaded_encrypted_aes_key} with type {type(loaded_encrypted_aes_key)} ')

    # Decrypt the AES key with the recipient's private RSA key
    loaded_aes_key = decrypt(loaded_encrypted_aes_key, privKey)
    print(f'D Loaded Decrypted AES Key    = {loaded_aes_key} with type {type(loaded_aes_key)}')

    # Convert the string AES key back to bytes
    decoded_aes_key = base64.b64decode(loaded_aes_key)
    print(f'E Loaded Decoded AES Key      = {decoded_aes_key} with type {type(decoded_aes_key)}')

    # Decrypt the bigFile.bin and save it to decrypted_file variable
    decrypted_file = decrypt_file_with_aes('bigFile.bin', decoded_aes_key)

    # Write a clone of bigFile.pdf from the decrypted file
    if decrypted_file:
        with open('bigFileClone.pdf', 'wb') as f:
            f.write(decrypted_file)
    else:
        print(f'Tampered File Detected')

    # Read the signature from signature.bin
    with open('signature.bin', 'rb') as f:
        bigFileSignature2 = f.read()
    print(bigFileSignature2)

    # Recipient verifies the signature with the sender's public key
    if verify_sha256(base64.b64encode(decrypted_file).decode(), bigFileSignature2, pubKey):
        print(f'Signature verified')
    else:
        print(f'Failed to verify')

    """
    Complete process:
    1. Create an aes key
    2. Encrypt the large file using the aes key (symmetric encryption)
    3. Encrypt the aes key using RSA with the recipient's public key (asymmetric encryption)
    4. Sign the large file using RSA with the sender's private key
    5. Recipient decrypts the encrypted aes key with the recipient's private key.
    6. Recipient decrypts the large file with the obtained plaintext aes key.
    7. Recipients verifies the signature with the plaintext large file and the sender's public key.
    """


if __name__ == '__main__':
    main()
