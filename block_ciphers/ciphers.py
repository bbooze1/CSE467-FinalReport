from typing import Tuple

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_symmetric_key_mode(
    public_rsa_file: str, 
    aes_key: bytes, 
    aes_mode: bytes,
) -> bytes:

    public_key = RSA.import_key(open(public_rsa_file).read())

    cipher_rsa = PKCS1_OAEP.new(public_key)

    enc_aes_key = cipher_rsa.encrypt(aes_key)
    enc_aes_mode = cipher_rsa.encrypt(aes_mode)

    return enc_aes_key + enc_aes_mode


def decrypt_symmetric_key_mode(
    private_rsa_file: str, 
    enc_data: bytes
) -> str:

    private_key = RSA.import_key(open(private_rsa_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    enc_aes_key = enc_data[0:private_key.size_in_bytes()]
    enc_data = enc_data[private_key.size_in_bytes():]

    enc_aes_mode = enc_data

    aes_key = cipher_rsa.decrypt(enc_aes_key)
    aes_mode = cipher_rsa.decrypt(enc_aes_mode)

    return aes_key, aes_mode


def encrypt_message(
    aes_key: bytes, 
    aes_mode: bytes, 
    data: str,
) -> bytes:

    if aes_mode == "AES-GCM".encode():
        nonce, tag, ciphertext = AES_GCM_encrypt(aes_key, data)
        return (nonce + tag + ciphertext)
    elif aes_mode == "AES-CBC".encode():
        iv, ciphertext = AES_CBC_encrypt(aes_key, data)
        return (iv + ciphertext)


def decrypt_message(
    enc_data: bytes,
    aes_key: bytes,
    aes_mode: bytes,
) -> str:

    byte_length = 16

    if aes_mode == "AES-GCM".encode():
        nonce = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        tag = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        ciphertext = enc_data

        plaintext = AES_GCM_decrypt(aes_key, nonce, tag, ciphertext)
        return plaintext

    elif aes_mode == "AES-CBC".encode():
        iv = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        ciphertext = enc_data

        plaintext = AES_CBC_decrypt(aes_key, iv, ciphertext)
        return plaintext


def AES_GCM_encrypt(
    aes_key: bytes, 
    data: str
) -> Tuple[bytes, bytes, bytes]:

    data = data.encode()

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    nonce = cipher_aes.nonce

    return nonce, tag, ciphertext


def AES_GCM_decrypt(
    aes_key: bytes, 
    nonce: bytes, 
    tag: bytes, 
    ciphertext: bytes
) -> str:

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode('utf-8')


def AES_CBC_encrypt(aes_key: bytes, data: str) -> Tuple[bytes, bytes]:
    data = data.encode()

    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    iv = cipher_aes.iv

    return iv, ciphertext


def AES_CBC_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    return plaintext.decode("utf-8")