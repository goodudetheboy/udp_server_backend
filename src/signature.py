import queue
import logging
from packet import PacketInfo, SIGNATURE_SIZE
from logger import LogRequest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

MODULUS_SIZE = 64
EXPONENT_SIZE = 3

def verify_signature(
        data: bytes,
        packet_info: PacketInfo,
        public_key: bytes,
        log_queue: queue.Queue[LogRequest],
        verif_logger: logging.Logger,
        delay: float = 0,
    ) -> bool:
    """
    Verify that the RSA 512 SHA-256 digital signature provided in the packet
    is correct. If it is not, the error will be logged to the file
    verification_failures.log in the format:
        (packet id - in hex)
        (packet sequence number)
        (received hash)
        (expected hash)
        (trailing newline)

    Args:
        data (bytes): data from this packet, including the digital signature
        packet_info (PacketInfo): info extracted from this packet
        public_key (bytes): Public key for the digital signature
    
    Returns:
        bool: True if the verification is valid, False otherwise.
    """
    data = data[:-SIGNATURE_SIZE]
    signature = packet_info.signature
    modulus = int.from_bytes(public_key[-MODULUS_SIZE:])
    exponent = int.from_bytes(public_key[:EXPONENT_SIZE])
    
    # Verify rsa signature and get back result, received, and expected for
    # logging
    res, rec, exp = _verify_rsa_signature(data, signature, modulus, exponent)

    if res is False:
        log = (f"{hex(packet_info.packet_id)}\n"
               f"{packet_info.packet_sequence_no}\n"
               f"{rec}\n"
               f"{exp}\n\n")
        log_queue.put(LogRequest(log, delay, verif_logger))
        logging.error("Digital signature validation failed for packet_id"
                     f" {hex(packet_info.packet_id)}, sequence number"
                     f" {packet_info.packet_sequence_no}.")

    return res


def _verify_rsa_signature(
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

