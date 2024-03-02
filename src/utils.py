import hmac
import hashlib

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

def hash_data_with_key(data, key):
    # Ensure the key and data are bytes
    key = key.encode('utf-8') if isinstance(key, str) else key
    data = data.encode('utf-8') if isinstance(data, str) else data

    # Calculate the HMAC using SHA256 as the hash function
    hashed_data = hmac.new(key, data, hashlib.sha256).digest()
    
    # Optionally, you can convert the binary digest to a hex or base64 representation
    hashed_data_hex = hashed_data.hex()
    hashed_data_base64 = hmac.new(key, data, hashlib.sha256).digest().hex()

    return hashed_data, hashed_data_hex, hashed_data_base64
