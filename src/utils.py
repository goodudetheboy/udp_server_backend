def print_bytes(bs: bytes):
    return f"{int.from_bytes(bs)} ({bs.hex()})"
