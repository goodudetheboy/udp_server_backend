import itertools
import socket
import argparse # for parsing arguments
import ast # args parsing support for dict conversion 
import utils


METADATA_BYTE_SIZE = 4 + 4 + 4 + 64

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

class ServerConfig:
    def __init__(
            self,
            host: str,
            port: int,
            keys: dict[int, bytes],
            binaries: dict[int, str],
            delay: float
        ):
        self.host = host
        self.port = port
        self.keys = keys
        self.binaries = binaries
        self.delay = delay

def udp_server(server_config: ServerConfig):

    host = server_config.host
    port = server_config.port

    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        # Bind the socket to a specific address and port
        server_socket.bind((host, port))
        print(f"UDP server listening on {host}:{port}")

        while True:
            # Receive data and address from client
            data, client_address = server_socket.recvfrom(2048)
            
            # Verify structural integrity of data
            packet_info = verify_integrity(data)
            if packet_info is None:
                print(f"Data received is invalid.")
                continue
            
            # if packet_info.packet_sequence_no != 1109:
            #     continue
            print(packet_info.get_info())

            # Check if have packet_id in keychain
            if packet_info.packet_id not in server_config.keys:
                print(f"No key provided for packet id"
                      f" 0x{hex(packet_info.packet_id)}")
                continue

            # Verify digital signature
            result = verify_signature(
                data,
                packet_info,
                server_config.keys[packet_info.packet_id]
            )

            if result is False:
                print(f"Digital signature validation failed for"
                      f" packet id 0x{packet_info.packet_id}.")

            # Verify checksums
            result = verify_checksums(
                packet_info,
                server_config.binaries[packet_info.packet_id]
            )

            if result is False:
                print(f"Checksums validation failed for"
                      f" packet id 0x{packet_info.packet_id}.")
            elif result is None:
                return
            print()
            # Echo back the received data to the client
            server_socket.sendto(data, client_address)

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
    if len(data) < METADATA_BYTE_SIZE:
        return None

    packet_id = int.from_bytes(data[0:4])
    packet_sequence_no = int.from_bytes(data[4:8])
    xor_key = data[8:10]
    no_of_checksum = int.from_bytes(data[10:12])

    # length of no checksum plus len of metadata must match length of input
    # byte array, aka no_of_checksum * 4 + METADATA_BYTE_SIZE == len(data)
    if no_of_checksum * 4 + METADATA_BYTE_SIZE != len(data):
        return None

    # rest of the part is valid, so pack into a PacketInfo and resend
    signature = data[-64:]
    checksums_data = data[12:-64]
    
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
        public_key: bytes
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
        packet_info (PacketInfo): info extracted from this package
        public_key (bytes): Public key for the digital signature
    
    Returns:
        bool: True if the verification is valid, False otherwise.
    """
    data = data[:-64]
    signature = packet_info.signature
    modulus = int.from_bytes(public_key[-64:])
    exponent = int.from_bytes(public_key[:3])
    
    result, received, expected = utils.verify_rsa_signature(data, signature, modulus, exponent)

    if result is True:
        print("\tSignature verification successful")
    else:
        with open("verification_failures.log", "a") as log_file:
            log_file.write(f"{hex(packet_info.packet_id)}\n"
                           f"{packet_info.packet_sequence_no}\n"
                           f"{received}\n"
                           f"{expected}\n\n")
        print("\tSignature verification failed, check verification_failures.log"
                " for more details")


def verify_checksums(
        packet_info: PacketInfo,
        binary_path: str
    ) -> bool:
    sequence_no = packet_info.packet_sequence_no
    xor_key = packet_info.xor_key
    no_of_checksum = packet_info.no_of_checksum
    
    # get data checksum, starting at bytes 12 and go all the way till the
    # digital signature
    checksums = utils.xor_decrypt(packet_info.checksums_data, xor_key)
    
    try:
        with open(binary_path, 'rb') as binary_file:
            binary_file.seek(1109 * 4)
            fuck = (binary_file.read(11 * 4))
            print(fuck.hex())
            # print(hex(utils.calculate_crc32_dword(fuck)))
            binary_file.seek(sequence_no * 4)
            # binary_file.seek(199989 * 4)
            # print(packet_info.no_of_checksum)
            # print(binary_file.read(packet_info.no_of_checksum * 4).hex())
            for i in range(0, no_of_checksum):
                print(sequence_no + i)
                expected = binary_file.read(4)
                if len(expected) == 0:
                    return None
                print(expected.hex())
                expected = utils.calculate_crc32_dword(expected)

                received = checksums[4 * i : 4 * i + 4]
                
                print("Received CRC32:", received.hex())
                print("Expected CRC32:", hex(expected))
                return
                if expected != received:
                    print("Checksum validation failed")

        # everything checks out, returns True
        print("Checksum validation successful")
        return True
    except FileNotFoundError:
        print(f"Error: Validating checksum failed because binary file not found" 
              f"for packet_id '{packet_info.packet_id}' at path '{binary_path}'")
        return False

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
            print(f"Warning: Key not found for packet_id '{packet_id}' at path"
                  f" '{key_path}'")

    return keys

def load_binaries(binaries_dict: dict[str, str]) -> dict[int, bytes]:
    binaries = {}

    for packet_id, binary_path in binaries_dict.items():
        # Convert key_id to int
        packet_id_int = utils.convert_packet_id_to_int(packet_id)

        # Load the content of the key file
        try:
            with open(binary_path, 'rb'):
                binaries[packet_id_int] = binary_path
        except FileNotFoundError:
            # If not found, warn 
            print(f"Warning: Binary path not found for packet_id '{packet_id}'"
                  f" at path '{binary_path}'")

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

    server_config = ServerConfig(host, port, keys_dict, binaries_dict, delay)

    # Start the UDP server
    udp_server(server_config)


if __name__ == "__main__":
    main()
