import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def aes_key_generation(
        byte_length: int, 
        aes_mode: str,
) -> bytes:
    """Generates a key for AES encryption using random bytes

    Args:
        byte_length: The amount of bytes you want the key to be
            Valid numbers are 16, 24, and 32. If using 24 bytes you can only use AES-CBC
        aes_mode: a string denoting whether AES-GCM or AES-CBC is being used

    Returns:
        A key of type byte that's been hashed using SHA256
    """

    # confirm that a 128, 192, or 256 bit key is being requested
    if byte_length != 16 and byte_length != 24 and byte_length != 32:
        return "can only compute a 16, 24, or 32 byte key"
    
    # confirm a valid AES method is being used with key length
    if byte_length == 24 and aes_mode == "AES-GCM":
        return "Can only use a 24 byte key with AES-CBC"
    
    # hash the random generated bytes to be the key and then return the hashed data
    hash_object = SHA256.new(data=get_random_bytes(byte_length))
    key = hash_object.digest()
    return key


def generate_rsa_keys(
        file_location: str ="."
) -> str:
    """Generates and saves a public/private key pair using RSA

    Args:
        file_location: Location you want the public and private keys to be saved.
            Default location is cwd

    Returns:
        A string containing whether the key creation was successful or not
    """

    try:
        # sufficient length to make RSA key
        key = RSA.generate(2048)

        # grab the public and private portions from the key
        private_key = key.export_key(pkcs=8,
                                protection="scryptAndAES128-CBC")
        
        public_key = key.publickey().export_key()
        
        # save both to separate files
        with open(os.path.join(file_location, "private.pem"), "wb") as file_out:
            file_out.write(private_key)

        with open(os.path.join(file_location, "public.pem"), "wb") as file_out:
            file_out.write(public_key)
        return "RSA keys made"

    except:
        return "Error making RSA keys"
