from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def print_bytes(bs: bytes):
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"

def print_int_hex(num: int):
    return f"{num} (0x{hex(num)})"

def convert_packet_id_to_int(packet_id: str):
    # Sanitize the data by removing leading and trailing whitespaces
    packet_id = packet_id.strip()

    if packet_id.isdigit():
        # If everything inside the given packet id is all numbers, treat it as base 10
        return int(packet_id)
    elif packet_id.startswith("0x"):
        # If it starts with "0x", treat it as hex
        return int(packet_id, 16)

def convert_dict_keys_to_bytes(original_dict):
    converted_dict = {}
    for key, value in original_dict.items():
        converted_key = convert_packet_id_to_int(key)
        converted_dict[converted_key] = value
    return converted_dict

def verify_rsa_signature(data: bytes, signature: bytes, modulus: int, exponent: int):   
    """
    Verify an RSA-512 SHA-256 digital signature for the given data.

    Args:
    - data (bytes): The data that was signed.
    - signature (bytes): The RSA511 SHA-256 digital signature to be verified.
    - modulus (int): the modulus value of the RSA-512
    - exponent (int): the modulus value of the RSA-512

    Returns:
    - valid: True if the signature is valid, False otherwise.
    """
    # Construct the public key
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    
    # Hash the data
    hasher = hashes.Hash(hashes.SHA256(), default_backend())
    hasher.update(data)
    hashed_data = hasher.finalize()
    expected = hashed_data.hex()
    print(f"Hashed Data: {hashed_data.hex()}")

    # Decrypt digital signature (manually do this because public_key.verify is dumb)
    result = pow(int.from_bytes(signature), exponent, modulus)
    received = hex(result)[-64:].removeprefix("0x").rjust(64, "0")
    print(f"Decoded Public Key Hash: {received}")

    # Verify the signature
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verification successful.")
        return True, received, expected
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False, received, expected