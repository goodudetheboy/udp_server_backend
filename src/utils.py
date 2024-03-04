from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import binascii
import os
import zlib
import struct


def print_bytes(bs: bytes) -> str:
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"

def print_int_hex(num: int) -> str:
    return f"{num} ({hex(num)})"

def convert_packet_id_to_int(packet_id: str) -> int:
    # Sanitize the data by removing leading and trailing whitespaces
    packet_id = packet_id.strip()

    if packet_id.isdigit():
        # If everything inside the given packet id is all numbers, treat it as base 10
        return int(packet_id)
    elif packet_id.startswith("0x"):
        # If it starts with "0x", treat it as hex
        return int(packet_id, 16)

def verify_rsa_signature(
        data: bytes,
        signature: bytes,
        modulus: int,
        exponent:
        int
    ) -> tuple[bool, str, str]:
    """
    Verify an RSA-512 SHA-256 digital signature for the given data.

    Args:
        data (bytes): The data that was signed
        signature (bytes): The RSA511 SHA-256 digital signature to be verified
        modulus (int): the modulus value of the RSA-512
        exponent (int): the modulus value of the RSA-512

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Construct the public key
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    
    # Hash the data
    hasher = hashes.Hash(hashes.SHA256(), default_backend())
    hasher.update(data)
    hashed_data = hasher.finalize()
    expected = hashed_data.hex()
    # print(f"Hashed Data: {hashed_data.hex()}")

    # Decrypt digital signature (manually do this because public_key.encrypt is
    # dumb)
    result = pow(int.from_bytes(signature), exponent, modulus)
    received = hex(result)[-64:].removeprefix("0x").rjust(64, "0")
    # print(f"Decoded Public Key Hash: {received}")

    # TODO: investigate why this doesn't work
    # received = public_key.encrypt(signature, padding=padding.PKCS1v15())

    # Verify the signature
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True, received, expected
    except Exception as e:
        return False, received, expected
    
def xor_decrypt(data: bytes, key: bytes):
    decrypted_data = bytearray()
    key_length = len(key)

    for i, byte in enumerate(data):
        decrypted_data.append(byte ^ key[i % key_length])

    return bytes(decrypted_data)

def calculate_crc32_dword(dword: bytes):
    # Calculate the CRC32 checksum for the single DWORD
    # print("cur dword ", data_dword.hex())
    # crc32_checksum = binascii.crc32(data_dword, 0xFFFFFFFF)
    crc32_checksum = zlib.crc32(dword)
    return crc32_checksum


def get_file_size(file_path):
    try:
        # Get the size of the file in bytes
        file_size = os.path.getsize(file_path)
        return file_size

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None