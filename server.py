import socket
import binascii

def split_hex_data(hex_data, chunk_size):
    # Split the hex data into chunks of the specified size
    return [hex_data[i:i+chunk_size] for i in range(0, len(hex_data), chunk_size)]

def udp_server(host, port):
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        # Bind the socket to a specific address and port
        server_socket.bind((host, port))
        print(f"UDP server listening on {host}:{port}")

        while True:
            # Receive data and address from client
            data, client_address = server_socket.recvfrom(1024)
            
            # Convert binary data to hexadecimal
            hex_data = binascii.hexlify(data).decode('utf-8')

            # Split hex data into lines with 4 characters each
            lines = split_hex_data(hex_data, 8)

            # Print received data in formatted lines and client address
            print(f"Received data from {client_address}:\n" + "\n".join(lines))
            print("end") 

            # Echo back the received data to the client
            server_socket.sendto(data, client_address)
if __name__ == "__main__":
    # Set the host and port for the server to listen on
    host = "127.0.0.1"  # Use "0.0.0.0" to listen on all available interfaces
    port = 1337

    # Start the UDP server
    udp_server(host, port)