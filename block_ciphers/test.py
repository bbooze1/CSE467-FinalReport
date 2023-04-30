import ciphers
import key_generation

byte_length = 16
aes_mode = "AES-GCM"
data = "This is a test"

aes_key = key_generation.aes_key_generation(byte_length)

message = key_generation.generate_rsa_keys()
print(message)

enc_data = ciphers.encrypt_message("public.pem", aes_key, aes_mode, data)

plaintext = ciphers.decrypt_message("private.pem", enc_data)
print(plaintext)