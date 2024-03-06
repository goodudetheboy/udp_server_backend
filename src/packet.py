import utils
import logging
import queue
import zlib
from logger import LogRequest

PKT_ID_SIZE = 4
PKT_SEQ_NO_SIZE = 4
XOR_KEY_SIZE = 2
NO_CKSUM_SIZE = 2
SIGNATURE_SIZE = 64
HEADER_SIZE = PKT_ID_SIZE + PKT_SEQ_NO_SIZE + XOR_KEY_SIZE + NO_CKSUM_SIZE
METADATA_SIZE = HEADER_SIZE + SIGNATURE_SIZE

MODULUS_SIZE = 64
EXPONENT_SIZE = 3


class PacketInfo:
    def __init__(
            self,
            packet_id: int,
            packet_sequence_no: int,
            xor_key: bytes,
            no_of_checksum: int,
            signature: bytes,
            checksums_data: bytes,
        ):
        self.packet_id = packet_id
        self.packet_sequence_no = packet_sequence_no
        self.xor_key = xor_key
        self.no_of_checksum = no_of_checksum
        self.signature = signature
        self.checksums_data = checksums_data

    def get_info(self) -> str:
        """
        Return the info containing the ID, packet sequence number, XOR key, and
        the number of checksums.
        """
        return (
            f"Packet ID: {utils.print_int_hex(self.packet_id)}\n"
            f"\tPacket Sequence No: {self.packet_sequence_no}\n"
            f"\tXOR key: {utils.print_bytes(self.xor_key)}\n"
            f"\tNumber of checksum: {self.no_of_checksum}"
        )

def verify_integrity(data: bytes) -> PacketInfo | None:
    """
    Verify the structural integrity of the given data packet as specified
    in the documentation. This first checks if the length of the given data
    is at least METADATA_BYTE_SIZE bytes, then once it retrieves the number
    of checksums, it will check if the total length of the data is equal to
    number of checksum * 4 + METADATA_BYTE_SIZE

    Args:
        data (bytes): raw input from the port.

    Returns:
        PacketInfo | None: return None if the data's structual integrity is 
        does not meet the above requirement. Return a PacketInfo containing
        the data's packet_id, packet_sequence_no, xor_key, and the number 
        of checksum.  

    """

    # Check that given input data has at least minimum size of metadata
    if len(data) < METADATA_SIZE:
        return None

    # retrieve packet_id
    packet_id = int.from_bytes(data[0 : PKT_ID_SIZE])
    ptr = PKT_ID_SIZE

    # retrieve packet sequence number
    packet_sequence_no = int.from_bytes(data[ptr : ptr + PKT_SEQ_NO_SIZE])
    ptr += PKT_SEQ_NO_SIZE

    # retrieve xor key
    xor_key = data[ptr : ptr + XOR_KEY_SIZE]
    ptr +=  XOR_KEY_SIZE

    # retrieve number of checksums
    no_of_checksum = int.from_bytes(data[ptr : ptr + NO_CKSUM_SIZE])

    # length of no checksum plus len of metadata must match length of input
    # byte array, aka no_of_checksum * 4 + METADATA_BYTE_SIZE == len(data)
    if no_of_checksum * 4 + METADATA_SIZE != len(data):
        return None

    # rest of the part is valid, so pack into a PacketInfo and resend
    signature = data[-SIGNATURE_SIZE:]
    checksums_data = data[HEADER_SIZE:-SIGNATURE_SIZE]
    
    return PacketInfo(
        packet_id,
        packet_sequence_no,
        xor_key,
        no_of_checksum,
        signature,
        checksums_data
    )

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
    res, rec, exp = utils.verify_rsa_signature(data, signature, modulus, exponent)

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
