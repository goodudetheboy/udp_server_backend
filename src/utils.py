def print_bytes(bs: bytes):
    return f"{int.from_bytes(bs)} (0x{bs.hex()})"
