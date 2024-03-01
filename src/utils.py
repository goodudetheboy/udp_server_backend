def print_bytes(bs: bytes):
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"

def convert_packet_id_to_bytes(packet_id: str):
    # Sanitize the data by removing leading and trailing whitespaces
    packet_id = packet_id.strip()

    if packet_id.isdigit():
        # If everything inside the given packet id is all numbers, treat it as base 10
        return int(packet_id).to_bytes((len(packet_id) + 1) // 2, byteorder="big")
    elif packet_id.startswith("0x"):
        # If it starts with "0x", treat it as hex
        return bytes.fromhex(packet_id[2:])
    else:
        # Treat it as a string
        return packet_id.encode("utf-8")

def convert_dict_keys_to_bytes(original_dict):
    converted_dict = {}
    for key, value in original_dict.items():
        converted_key = convert_packet_id_to_bytes(key)
        converted_dict[converted_key] = value
    return converted_dict
