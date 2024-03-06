import socket
import argparse
import ast
import queue
import threading
import logging
from logger import LogRequest, delayed_logger_thread
from packet import PacketInfo, verify_integrity
from checksums import FileChecksums, verify_checksums
from signature import verify_signature


VERIF_FAILURES_LOG_PATH = "verification_failures.log"
CKSUMS_FAILURE_LOG_PATH = "checksum_failures.log"

logging.basicConfig(
    level=logging.INFO,
    encoding='utf-8',
    format="%(asctime)s [%(levelname)s] %(message)s"
)

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
            server_config.verif_logger,
            server_config.delay
        )
        if signature_result is False:
            continue
            
        # Verify checksums
        checksums_result = verify_checksums(
            packet_info,
            file_checksums,
            log_queue,
            server_config.cksum_logger,
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

def _load_keys(keys_dict: dict[str, str]) -> dict[int, bytes]:
    keys = {}

    for packet_id, key_path in keys_dict.items():
        # Convert key_id to int
        packet_id_int = int(packet_id, 16)

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

def _load_binaries(binaries_dict: dict[str, str]) -> dict[int, FileChecksums]:
    binaries = {}

    for packet_id, binary_path in binaries_dict.items():
        # Convert key_id to int
        packet_id_int = int(packet_id, 16)

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
    keys_dict = _load_keys(keys_dict) # sanitize keys
    binaries_dict = {} if args.binaries is None else args.binaries
    binaries_dict = _load_binaries(binaries_dict) # sanitize bins
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
