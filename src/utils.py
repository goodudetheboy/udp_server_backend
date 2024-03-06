
def print_bytes(bs: bytes) -> str:
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"

def print_int_hex(num: int) -> str:
    return f"{num} ({hex(num)})"

def convert_packet_id_to_int(packet_id: str) -> int:
    # Sanitize the data by removing leading and trailing whitespaces
    packet_id = packet_id.strip()

    if packet_id.isdigit():
        # If everything inside the given packet id is all numbers, treat it as base 10
        return int(packet_id)
    elif packet_id.startswith("0x"):
        # If it starts with "0x", treat it as hex
        return int(packet_id, 16)
