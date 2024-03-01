import socket
import binascii
import argparse # for parsing arguments
import ast # args parsing support for dict conversion 
import json
import utils

METADATA_BYTE_SIZE = 4 + 4 + 4 + 64

class PacketInfo:
    def __init__(self, packet_id: bytes, packet_sequence_no: bytes, xor_key: bytes, no_of_checksum: int):
        self.packet_id = packet_id
        self.packet_sequence_no = packet_sequence_no
        self.xor_key = xor_key
        self.no_of_checksum = no_of_checksum

    def get_info(self):
        return f"Packet ID: {utils.print_bytes(self.packet_id)}\n\tPacket Sequence No: {utils.print_bytes(self.packet_sequence_no)}\n\tXOR key: {utils.print_bytes(self.xor_key)}\n\tNumber of checksum: {self.no_of_checksum}"

class ServerConfig:
    def __init__(self, host, port, keys, binaries, delay):
        self.host = host
        self.port = port
        self.keys = keys
        self.binaries = binaries
        self.delay = delay

def split_hex_data(hex_data, chunk_size):
    # Split the hex data into chunks of the specified size
    return [hex_data[i:i+chunk_size] for i in range(0, len(hex_data), chunk_size)]

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
            
            # Convert binary data to hexadecimal
            hex_data = binascii.hexlify(data).decode('utf-8')

            # Split hex data into lines with 4 characters each
            lines = split_hex_data(hex_data, 8)

            packet_info = verify_integrity(data)

            if packet_info is None:
                print(f"Data received is invalid.")
                continue
            
            print(packet_info.get_info())
            # Print received data in formatted lines and client address
            # print(f"Received data from {client_address}:\n" + "\n".join(lines))
            # print("end") 

            # Echo back the received data to the client
            server_socket.sendto(data, client_address)

def verify_integrity(data):   
    """
    Verify the structural integrity of the given data packet as specified
    in the documentation. This first checks if the length of the given data
    is at least METADATA_BYTE_SIZE bytes, then once it retrieves the number
    of checksums, it will check if the total length of the data is equal to
    number of checksum * 4 + METADATA_BYTE_SIZE

    Args:
        data (bytes): raw input from the port.

    Returns:
        None | PacketInfo: return None if the data's structual integrity is 
        does not meet the above requirement. Return a PacketInfo containing
        the data's packet_id, packet_sequence_no, xor_key, and the number 
        of checksum.  

    """

    # Check that given input data has at least minimum size of metadata
    if len(data) < METADATA_BYTE_SIZE:
        return None

    packet_id = data[0:4]
    packet_sequence_no = data[4:8]
    xor_key = data[8:10]
    no_of_checksum = int.from_bytes(data[10:12])

    # length of no checksum plus len of metadata must match length of input
    # byte array
    # no_of_checksum * 4 + METADATA_BYTE_SIZE == len(data)
    if no_of_checksum * 4 + METADATA_BYTE_SIZE != len(data):
        return None
    
    return PacketInfo(packet_id, packet_sequence_no, xor_key, no_of_checksum)

def main():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser()

    # Add named arguments
    parser.add_argument('--keys', type=ast.literal_eval, help='Dictionary of {packet_id: key_file_path} mappings')
    parser.add_argument('--binaries', type=ast.literal_eval, help='Dictionary of {packet_id: binary_path} mappings')
    parser.add_argument('-d', '--delay', type=float, help='Delay (in seconds) for writing to log files')
    parser.add_argument('-p', '--port', type=int, help='Port number to receive packets on')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Preparing config for UDP server
    host = "127.0.0.1"
    keys_dict = {} if args.keys is None else json.loads(args.keys)
    binaries_dict = {} if args.binaries is None else json.loads(args.binaries)
    delay = 0 if args.delay is None else args.delay
    port = 1337 if args.port is None else args.port

    server_config = ServerConfig(host, port, keys_dict, binaries_dict, delay)

    # Start the UDP server
    udp_server(server_config)


if __name__ == "__main__":
    main()

# def verify_signature(data, packet_info: PacketInfo):
