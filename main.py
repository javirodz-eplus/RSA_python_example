# This is a sample Python script.
import rsa
import rsa.randnum

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


def encrypt(text, key):
    return rsa.encrypt(text.encode('ascii'), key)


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


def main():
    # Key filename
    pubKeyFile = "pubkey.pem"
    privKeyFile = "privkey.pem"

    # Uncomment the next line to generate a new RSA public/private key pair
    # generate_keys(pubKeyFile, privKeyFile)

    pubKey, privKey = load_keys(pubKeyFile, privKeyFile)

    # Some message in plaintext
    original_message = "Plaintext Message"

    # Sender encrypts the message with the recipient's public key. In this case, only the recipient can decrypt the
    # ciphertext with the private key (Confidentiality).
    # Encrypt with the public key (Sender)
    ciphertext = encrypt(original_message, pubKey)
    # Decrypt with the private key (Receiver)
    plaintext = decrypt(ciphertext, privKey)
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

    """
    # RSA cannot encrypt a file larger than the key (minus some random padding(
    # A 512 bit (64 bytes) RSA key can be used to encrypt a 63 byte file.
    The most common way to use RSA with larger files uses a block cypher like AES or DES3 to encrypt the file 
    with a random key, then encrypt the random key with RSA.You would send the encrypted file along with the 
    encrypted key to the recipient.The complete flow is:
    """
    aes_key = rsa.randnum.read_random_bits(128)
    #
    # TODO: Use aes_key to encrypt the large file with AES
    #
    # Encrypt the aes_key with RSA
    encrypted_aes_key = encrypt(aes_key, pubKey)
    #
    # TODO: Send the encrypted file together with the encrypted_aes_key
    # TODO: The recipient reverses the process to obtain the plaintext file
    # 1. RSA Decrypt the encrypted_aes key with the sender's public key to get the plaintext aes_key
    # 2. AES Decrypt the encrypted file using the aes_key
    # Note: The Python-RSA module does not contain functionality to do the AES encryption for you.
    # Source: 5.4. Working with big files
    # https://stuvel.eu/python-rsa-doc/usage.html#encryption-and-decryption
    # To keep the integrity, also include the signature of the file.
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
