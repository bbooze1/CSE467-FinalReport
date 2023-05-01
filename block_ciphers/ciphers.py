from typing import Tuple

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA


def encrypt_symmetric_key_mode(
    public_rsa_file: str, 
    aes_key: bytes, 
    aes_mode: str,
) -> Tuple[bytes, bytes]:
    """Encrypts the symmetric key and encryption mode specified

    Args:
        public_rsa_file: file containing the contents of the public RSA key
        aes_key: symmetric key being used
        aes_mode: a string denoting whether AES-GCM, AES-CBC, or ChaCha20_Poly1305 is being used

    Returns:
        bytes: the key encrypted using the RSA public key
        bytes: the mode encrypted using the RSA public key
    """

    public_key = RSA.import_key(open(public_rsa_file).read())

    cipher_rsa = PKCS1_OAEP.new(public_key)

    enc_aes_key = cipher_rsa.encrypt(aes_key)
    enc_aes_mode = cipher_rsa.encrypt(aes_mode.encode())

    return enc_aes_key, enc_aes_mode


def decrypt_symmetric_key_mode(
    private_rsa_file: str, 
    enc_aes_key: bytes, 
    enc_aes_mode: bytes,
) -> Tuple[bytes, str]:
    """Decrypts the symmetric key and encryption mode specified

    Args:
        private_rsa_file: file containing the contents of the private RSA key
        aes_key: encrypted symmetric key being used
        aes_mode: an encrypted string denoting whether AES-GCM, AES-CBC, or ChaCha20_Poly1305 is being used

    Returns:
        bytes: the key decrypted using the RSA private key
        str: the mode decrypted using the RSA private key
    """

    private_key = RSA.import_key(open(private_rsa_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    aes_key = cipher_rsa.decrypt(enc_aes_key)
    aes_mode = cipher_rsa.decrypt(enc_aes_mode)

    return aes_key, aes_mode.decode()


def encrypt_message(
    aes_key: bytes, 
    aes_mode: str, 
    data: str,
) -> bytes:
    
    """Encrypts the message using the specified encryption method

    Args:
        aes_key: symmetric key being used
        aes_mode: a string denoting whether AES-GCM, AES-CBC, or ChaCha20_Poly1305 is being used
        data: plaintext that you want to encrypt

    Returns:
        bytes: The encrypted text along with the nonce and tag, or iv.
    """

    if aes_mode == "ChaCha20_Poly1305":
        nonce, tag, ciphertext = ChaCha20_Poly1305_encrypt(aes_key, data)
        return (nonce + tag + ciphertext)
    elif aes_mode == "AES-GCM":
        nonce, tag, ciphertext = AES_GCM_encrypt(aes_key, data)
        return (nonce + tag + ciphertext)
    elif aes_mode == "AES-CBC":
        iv, ciphertext = AES_CBC_encrypt(aes_key, data)
        return (iv + ciphertext)


def decrypt_message(
    enc_data: bytes,
    aes_key: bytes,
    aes_mode: str,
) -> str:
    
    """Decrypts the message using the specified encryption method

    Args:
        enc_data: encrypted data that you want to decrypt
        aes_key: symmetric key being used
        aes_mode: a string denoting whether AES-GCM, AES-CBC, or ChaCha20_Poly1305 is being used

    Returns:
        str: The decrypted text
    """

    byte_length = 16

    if aes_mode == "ChaCha20_Poly1305":
        nonce = enc_data[0:12]
        enc_data = enc_data[12:]

        tag = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        ciphertext = enc_data

        plaintext = ChaCha20_Poly1305_decrypt(aes_key, nonce, tag, ciphertext)
        return plaintext
    
    elif aes_mode == "AES-GCM":
        nonce = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        tag = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        ciphertext = enc_data

        plaintext = AES_GCM_decrypt(aes_key, nonce, tag, ciphertext)
        return plaintext

    elif aes_mode == "AES-CBC":
        iv = enc_data[0:byte_length]
        enc_data = enc_data[byte_length:]

        ciphertext = enc_data

        plaintext = AES_CBC_decrypt(aes_key, iv, ciphertext)
        return plaintext


def AES_GCM_encrypt(
    aes_key: bytes, 
    data: str,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypts data using the AES-GCM algorithm

    Args:
        aes_key: symmetric key being used
        data: data you want encrypted

    Returns:
        bytes: nonce
        bytes: tag
        bytes: ciphertext
    """
    
    data = data.encode()

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    nonce = cipher_aes.nonce

    return nonce, tag, ciphertext


def AES_GCM_decrypt(
    aes_key: bytes, 
    nonce: bytes, 
    tag: bytes, 
    ciphertext: bytes,
) -> str:
    """Decrypts data using the AES-GCM algorithm

    Args:
        aes_key: symmetric key being used
        nonce: value used with key to decrypt the data
        tag: value used to verify the message hasn't been tampered with
        ciphertext: data you want decrypted

    Returns:
        str: decrypted data
    """

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode('utf-8')


def AES_CBC_encrypt(
    aes_key: bytes, 
    data: str,
) -> Tuple[bytes, bytes]:
    """Encrypts data using the AES-CBC algorithm

    Args:
        aes_key: symmetric key being used
        data: data you want encrypted

    Returns:
        bytes: iv
        bytes: ciphertext
    """

    data = data.encode()

    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    iv = cipher_aes.iv

    return iv, ciphertext


def AES_CBC_decrypt(
    aes_key: bytes, 
    iv: bytes, 
    ciphertext: bytes,
) -> str:
    """Decrypts data using the AES-CBC algorithm

    Args:
        aes_key: symmetric key being used
        iv: value used with key to decrypt the data
        ciphertext: data you want decrypted

    Returns:
        str: decrypted data
    """

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    return plaintext.decode("utf-8")


def ChaCha20_Poly1305_encrypt(
    key: bytes, 
    data: str
) -> Tuple[bytes, bytes, bytes]:
    """Encrypts data using the ChaCha20_Poly1305 algorithm

    Args:
        key: symmetric key being used
        data: data you want encrypted

    Returns:
        bytes: nonce
        bytes: tag
        bytes: ciphertext
    """

    data = data.encode()

    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce

    return nonce, tag, ciphertext


def ChaCha20_Poly1305_decrypt(
    key: bytes, 
    nonce: bytes, 
    tag: bytes,
    ciphertext: bytes
) -> str:
    """Decrypts data using the haCha20_Poly1305 algorithm

    Args:
        key: symmetric key being used
        nonce: value used with key to decrypt the data
        tag: value used to verify the message hasn't been tampered with
        ciphertext: data you want decrypted

    Returns:
        str: decrypted data
    """

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode("utf-8")