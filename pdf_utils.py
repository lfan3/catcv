from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# PBKDF2 is the most widespread algorithm for deriving keys from a password
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64


def encrypt_aes(inputpath, outputpath, password):
    with open(inputpath, 'rb') as file:
        pdf_data = file.read()
    salt = get_random_bytes(16)
    # Longueur de la clé (32 bytes pour AES-256)
    # specifier SHA256 pour eviter le probleme du dechiffrement a cause de divergence d'algo
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    # initial vector of 16-byte
    iv = get_random_bytes(16)
    # Create cipher, CBC requires a multiple of block size(16 bytes)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad data
    pad_length = 16 - (len(pdf_data) % 16)
    # bytes can convert objects into bytes objects, or create empty bytes object of the specified size.
    # create pad_length's bytes
    padded_data = pdf_data + bytes([pad_length] * pad_length)
    # Encrypt
    encrypted_data = cipher.encrypt(padded_data)
    # Combine salt + iv + encrypted data
    final_data = salt + iv + encrypted_data
    # Convert to base64
    encrypted_base64 = base64.b64encode(final_data).decode('utf-8')
    with open(outputpath, 'w') as file:
        file.write(encrypted_base64)

def dycrpt_aes(inputpath, outputpath, password):
    with open(inputpath, 'rb') as file:
        encrypted_base64 = file.read()
    # b64decode: Décode un objet octet-compatible ou une chaîne de caractères ASCII s encodée
    #  en base64 et renvoie les bytes décodés.
    final_data = base64.b64decode(encrypted_base64)
    salt = final_data[:16]
    iv = final_data[16:32]
    encrypted_data = final_data[32:]
    # derive key
    key = PBKDF2(password, salt, dkLen=32,count=1000000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    if len(padded_data) == 0:
        raise ValueError("Données déchiffrées vides - mot de passe incorrect ?")
    pad_length = padded_data[-1]
    if pad_length <1 or pad_length > 16:
        raise ValueError("Padding invalide - possible corruption de données")
    pdf_data = padded_data[:-pad_length]
    with open(outputpath, 'wb') as file:
        file.write(pdf_data)
    return "Déchiffrement réussi"

# encrypt_pdf('./catcv.pdf', './catcv_encrypted.pdf','password')
# encrypt_aes('./catcv.pdf','./catcv_aes.pdf', 'password')
dycrpt_aes('./catcv_aes.pdf','./catcv_de.pdf', 'password')
