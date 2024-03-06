import queue
import zlib
import logging
from packet import PacketInfo
from logger import LogRequest

class FileChecksums:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.checksums: list[int] = []

    def calc_checksum(self, iter: int) -> int:
        checksums = self.checksums

        # check if input iteration are already calculated
        # if not then continue calculating
        if len(checksums) <= iter:
            binary_data = None
            try:
                with open(self.binary_path, "rb") as binary_file:
                    binary_data = binary_file.read()
            except FileNotFoundError:
                raise FileNotFoundError
            while len(checksums) <= iter:
                prev = 0 if len(checksums) == 0 else checksums[-1]
                new_chksum = zlib.crc32(binary_data, prev)
                checksums.append(new_chksum)
        
        return checksums[iter]


def verify_checksums(
        packet_info: PacketInfo,
        file_checksums: FileChecksums,
        log_queue: queue.Queue[LogRequest],
        cksum_logger: logging.Logger,
        delay: float = 0
    ) -> bool:
    """
    Verify that the incoming XOR'd Cyclic Checksum CRC32 DWORDS are valid.

    Args:
        packet_info (PacketInfo): info extracted from this packet
        file_checksums (FileChecksums): object containing the previously
            calculated checksums of a given file
    
    Returns:
        bool: True if the verification is valid, False otherwise.
    """
    sequence_no = packet_info.packet_sequence_no
    xor_key = packet_info.xor_key
    no_of_checksum = packet_info.no_of_checksum
    
    # get data checksum, starting at bytes 12 and go all the way till the
    # digital signature
    checksums = xor_decrypt(packet_info.checksums_data, xor_key)
    
    is_success = True
    # pre-calculate
    try:
        file_checksums.calc_checksum(sequence_no + no_of_checksum-1)
    except FileNotFoundError:
        logging.warning(f"Checksum validation failed because the file at"
                f"'{file_checksums.binary_path}' cannot be found.")
        return False

    for i in range(0, no_of_checksum):
        # calculate expected
        expected = file_checksums.calc_checksum(sequence_no + i)

        # calculated received
        received = int.from_bytes(checksums[4 * i : 4 * i + 4])
        
        if expected != received:
            is_success = False
            log = (f"{hex(packet_info.packet_id)}\n"
                   f"{packet_info.packet_sequence_no}\n"
                   f"{packet_info.packet_sequence_no + i}\n"
                   f"{hex(received)[2:]}\n"
                   f"{hex(expected)[2:]}\n\n")
            log_queue.put(LogRequest(log, delay, cksum_logger))
            logging.error("Checksum validation failed for packet_id"
                         f" {hex(packet_info.packet_id)}, cyclic iteration"
                         f" {sequence_no + i}.")

    # returns status 
    return is_success

def xor_decrypt(data: bytes, key: bytes):
    decrypted_data = bytearray()
    key_length = len(key)

    for i, byte in enumerate(data):
        decrypted_data.append(byte ^ key[i % key_length])

    return bytes(decrypted_data)

