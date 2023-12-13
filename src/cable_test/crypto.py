import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_PURPOSE_EID_KEY = 1
KEY_PURPOSE_TUNNEL_ID = 2
KEY_PURPOSE_PSK = 3


def generate_keys():
    identity_key = ec.generate_private_key(ec.SECP256R1())
    # identity_key_file = open('/tmp/identity.key', 'wb')
    # identity_key_file.write(identity_key.private_bytes(
    #     encoding=serialization.Encoding.DER,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # ))
    identity_public_key = identity_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.CompressedPoint)
    qr_secret = secrets.token_bytes(16)
    return (identity_key, identity_public_key, qr_secret)



def derive(qr_secret, salt, key_purpose, key_len):
    if key_purpose > 0x100:
        raise Exception("unsupported purpose")

    info = key_purpose.to_bytes(4, byteorder='little')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        info=info
    )

    return hkdf.derive(qr_secret)


def decrypt_ble_advertisement(secret, candidate_advert) -> bytes:
    eid_key = derive(secret, None, KEY_PURPOSE_EID_KEY, 32 + 32)
    zeros = [0] * 16
    if len(candidate_advert) != 20:
        raise Exception("Invalid candidate advertisement received")
        return (zeros, False)

    msg = candidate_advert[:16]
    tag = candidate_advert[16:]

    hmac_key = eid_key[32:]
    expected_tag = hmac.digest(hmac_key, msg, 'sha256')[:4]
    if not hmac.compare_digest(expected_tag[:4], tag):
        raise Exception("Ciphertext failed authentication")
    
    encryption_key = eid_key[:32]
    aes = algorithms.AES256(encryption_key)
    cipher = Cipher(aes, mode=modes.ECB())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(msg) + decryptor.finalize()
    return plaintext