

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import zlib

AES_KEY_SIZE = 16 #16 = 128-bit


def crc32_file(file_path):
    with open(file_path, 'rb') as f:
        crc = 0
        while True:
            chunk = f.read(1024)  # Read 1 KB at a time
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
    return crc



def generate_aes_cbc_key(rsa_key_bytes):
    # import rsa from bytes
    rsa_key = RSA.import_key(rsa_key_bytes)
    # Generate a 128-bit AES key
    aes_key = get_random_bytes(AES_KEY_SIZE)
    # Encrypt the AES key using RSA encryption in CBC mode
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    return [aes_key, encrypted_aes_key]
    

def decrypt_with_cbc(encrypted_text, key):
    # Create an AES cipher object with CBC mode and the given key and IV
    iv = b'\x00' * AES_KEY_SIZE
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the message using the AES cipher
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES_KEY_SIZE)
    # Print the decrypted message
    return decrypted_text







