import time
import random
import socket
import argparse # for parsing arguments
import ast # args parsing support for dict conversion 
import utils
import zlib
import queue
import threading
import logging
from logger import *

PKT_ID_SIZE = 4
PKT_SEQ_NO_SIZE = 4
XOR_KEY_SIZE = 2
NO_CKSUM_SIZE = 2
SIGNATURE_SIZE = 64
HEADER_SIZE = PKT_ID_SIZE + PKT_SEQ_NO_SIZE + XOR_KEY_SIZE + NO_CKSUM_SIZE
METADATA_SIZE = HEADER_SIZE + SIGNATURE_SIZE

MODULUS_SIZE = 64
EXPONENT_SIZE = 3

VERIF_FAILURES_LOG_PATH = "verification_failures.log"
CKSUMS_FAILURE_LOG_PATH = "checksum_failures.log"

logging.basicConfig(
    level=logging.INFO,
    encoding='utf-8',
    format="%(asctime)s [%(levelname)s] %(message)s"
)


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

class ServerConfig:
    def __init__(
            self,
            host: str,
            port: int,
            keys: dict[int, bytes],
            binaries: dict[int, FileChecksums],
            delay: float,
            verif_logger: logging.Logger,
            cksum_logger: logging.Logger,
            exit_event: threading.Event
        ):
        self.host = host
        self.port = port
        self.keys = keys
        self.binaries = binaries
        self.delay = delay
        self.verif_logger = verif_logger
        self.cksum_logger = cksum_logger
        self.exit_event = exit_event

def worker_thread(
        packet_id: int,
        work_queue: queue.Queue[(bytes, PacketInfo)],
        server_config: ServerConfig
    ) -> None:
    """
    A thread for processing digital signature and checksums validation. Will
    spawn a logger thread for use when needed to log failures.

    Args:
        packet_id (int): packet_id that this logger is assigned to process
        work_queue (queue.Queue[LogRequest]): queue to process packets
        server_config (ServerConfig): config of the UDP server

    """
    logging.info(f"Worker processing packet_id {hex(packet_id)} starting up.")

    log_queue = queue.Queue[LogRequest]()
    # Create logger thread
    logger_thread_instance = threading.Thread(
        target=delayed_logger_thread,
        args=(
            packet_id,
            log_queue,
            server_config.exit_event
        )
    )
    logger_thread_instance.start()

    # Load public key and file checksums for given packet_id
    public_key = server_config.keys[packet_id]
    file_checksums = server_config.binaries[packet_id]

    # Keep running until terminated 
    while not server_config.exit_event.is_set():
        # Fetch data from packet queue
        try:
            data, packet_info = work_queue.get(block=True, timeout=1)
        except queue.Empty:
            continue

        # Verify digital signature
        signature_result = verify_signature(
            data,
            packet_info,
            public_key,
            log_queue,
            server_config,
            server_config.delay
        )
        if signature_result is False:
            continue
            
        # Verify checksums
        checksums_result = verify_checksums(
            packet_info,
            file_checksums,
            log_queue,
            server_config,
            server_config.delay
        )
        if not checksums_result:
            continue
    
    logging.info(f"Worker processing {packet_id} shutting down.")

def _recv(server_socket: socket.socket) -> bytes:
    buffer = b""
    data = server_socket.recv(4096)
    buffer += data
    return buffer

def udp_server(server_config: ServerConfig):

    host = server_config.host
    port = server_config.port

    workers_queue: dict[int, (bytes, queue.Queue[PacketInfo])] = {}

    try:
        # Create a UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            # Bind the socket to a specific address and port
            server_socket.bind((host, port))
            logging.info(f"UDP server listening on {host}:{port}")

            while True:
                # Receive data and address from client, guarantee that packet
                # are received fully
                buffer = _recv(server_socket)

                # Verify structural integrity of data
                packet_info = verify_integrity(buffer)
                if packet_info is None:
                    logging.error(f"Incoming packet has invalid format.")
                    continue
                
                # If packets are valid, then we validate next 
                packet_id = packet_info.packet_id

                # TOREMOVE
                packet_id = random.randint(packet_id, packet_id + 4)
                packet_info.packet_id = packet_id

                # Check if have packet_id in keychain
                if packet_id not in server_config.keys:
                    logging.error(f"No key provided for packet_id"
                                f" {hex(packet_info.packet_id)}")
                    continue
                
                # Put packet to the worker handling the verifying packets with
                # specific packet_id
                if packet_id not in workers_queue:
                    worker_queue = queue.Queue()
                    workers_queue[packet_id] = worker_queue
                    worker_thread_instance = threading.Thread(
                        target=worker_thread,
                        args=(
                            packet_id,
                            worker_queue,
                            server_config
                        )
                    )
                    worker_thread_instance.start()

                workers_queue[packet_id].put((buffer, packet_info))

                # Echo back the received data to the client
    except KeyboardInterrupt:
        logging.info("Server terminated by user.")
    finally:
        # Kill all threads
        server_config.exit_event.set()
        server_socket.close()

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
        server_config: ServerConfig,
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
        log_queue.put(LogRequest(log, delay, server_config.verif_logger))
        logging.error("Digital signature validation failed for packet_id"
                     f" {hex(packet_info.packet_id)}, sequence number"
                     f" {packet_info.packet_sequence_no}.")

    return res

def verify_checksums(
        packet_info: PacketInfo,
        file_checksums: FileChecksums,
        log_queue: queue.Queue[LogRequest],
        server_config: ServerConfig,
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
    checksums = utils.xor_decrypt(packet_info.checksums_data, xor_key)
    
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
            log_queue.put(LogRequest(log, delay, server_config.cksum_logger))
            logging.error("Checksum validation failed for packet_id"
                         f" {hex(packet_info.packet_id)}, cyclic iteration"
                         f" {sequence_no + i}.")

    # returns status 
    return is_success

def load_keys(keys_dict: dict[str, str]) -> dict[int, bytes]:
    keys = {}

    for packet_id, key_path in keys_dict.items():
        # Convert key_id to int
        packet_id_int = utils.convert_packet_id_to_int(packet_id)

        # Load the content of the key file
        try:
            with open(key_path, 'rb') as key_file:
                key_content = key_file.read()
            keys[packet_id_int] = key_content
        except FileNotFoundError:
            # If not found, warn 
            logging.warning(f"Key not found for packet_id '{packet_id}' at path"
                  f" '{key_path}'")

    return keys

def load_binaries(binaries_dict: dict[str, str]) -> dict[int, FileChecksums]:
    binaries = {}

    for packet_id, binary_path in binaries_dict.items():
        # Convert key_id to int
        packet_id_int = utils.convert_packet_id_to_int(packet_id)

        # Load the content of the key file
        try:
            with open(binary_path, 'rb'):
                binaries[packet_id_int] = FileChecksums(binary_path)
        except FileNotFoundError:
            # If not found, warn 
            logging.warning(f"Binary file path not found for packet_id"
                  f" {packet_id} at path '{binary_path}'")

    return binaries


def main():
    # Parser object to parse named args
    parser = argparse.ArgumentParser()

    parser.add_argument('--keys', type=ast.literal_eval)
    parser.add_argument('--binaries', type=ast.literal_eval)
    parser.add_argument('-d', '--delay', type=float)
    parser.add_argument('-p', '--port', type=int)

    # Parse the command-line arguments
    args = parser.parse_args()

    # Prepare config for UDP server
    host = "127.0.0.1"
    keys_dict = {} if args.keys is None else args.keys
    keys_dict = load_keys(keys_dict) # sanitize keys
    binaries_dict = {} if args.binaries is None else args.binaries
    binaries_dict = load_binaries(binaries_dict) # sanitize bins
    delay = 0 if args.delay is None else args.delay
    port = 1337 if args.port is None else args.port


    # Set up thread-safe logging for verifications
    verif_handler = logging.FileHandler(VERIF_FAILURES_LOG_PATH)
    verif_logger = logging.getLogger("verification")
    verif_logger.addHandler(verif_handler)
    verif_logger.propagate = False

    # Set up thread-safe logging for checksums
    cksum_handler = logging.FileHandler(CKSUMS_FAILURE_LOG_PATH)
    cksum_logger = logging.getLogger("checksum")
    cksum_logger.addHandler(cksum_handler)
    cksum_logger.propagate = False

    # Exit event to stop threads
    exit_event = threading.Event()

    server_config = ServerConfig(
        host,
        port,
        keys_dict,
        binaries_dict,
        delay,
        verif_logger,
        cksum_logger,
        exit_event
    )

    # Start the UDP server
    udp_server(server_config)


if __name__ == "__main__":
    main()
