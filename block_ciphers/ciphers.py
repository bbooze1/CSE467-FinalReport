from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_message(public_rsa_file, aes_key, aes_mode, data):
    aes_mode = bytes(aes_mode, 'utf-8')

    public_key = RSA.import_key(open(public_rsa_file).read())

    cipher_rsa = PKCS1_OAEP.new(public_key)

    enc_aes_key = cipher_rsa.encrypt(aes_key)
    enc_aes_mode = cipher_rsa.encrypt(aes_mode)

    if aes_mode == bytes("AES-GCM", 'utf-8'):
        nonce, tag, ciphertext = AES_GCM_encrypt(aes_key, data)
        return (enc_aes_mode + enc_aes_key + nonce + tag + ciphertext)


def decrypt_message(private_rsa_file, enc_data):
    byte_length = 16

    private_key = RSA.import_key(open(private_rsa_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    enc_aes_mode = enc_data[0:private_key.size_in_bytes()]
    enc_data = enc_data[private_key.size_in_bytes():]
    
    enc_aes_key = enc_data[0:private_key.size_in_bytes()]
    enc_data = enc_data[private_key.size_in_bytes():]

    nonce = enc_data[0:byte_length]
    enc_data = enc_data[byte_length:]

    tag = enc_data[0:byte_length]
    enc_data = enc_data[byte_length:]

    ciphertext = enc_data

    aes_key = cipher_rsa.decrypt(enc_aes_key)
    aes_mode = cipher_rsa.decrypt(enc_aes_mode)

    if aes_mode == bytes("AES-GCM", 'utf-8'):
        plaintext = AES_GCM_decrypt(aes_key, nonce, tag, ciphertext)
        return plaintext


def AES_GCM_encrypt(aes_key, data):
    data = bytes(data, "utf-8")

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    nonce = cipher_aes.nonce

    return nonce, tag, ciphertext


def AES_GCM_decrypt(aes_key, nonce, tag, ciphertext):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode('utf-8')
