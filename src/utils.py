
def print_bytes(bs: bytes) -> str:
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"

def print_int_hex(num: int) -> str:
    return f"{num} ({hex(num)})"