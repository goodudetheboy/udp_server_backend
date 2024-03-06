import zlib

def calculate_crc32(file_path, iterations=200000, chunk_size=8192):
    crc32_result = 0

    with open(file_path, 'rb') as file:
        for i in range(iterations):
            print("iter", i)
            chunk = file.read()
            if not chunk:
                file.seek(0)  # Reset file position to the beginning when reaching the end
            crc32_result = zlib.crc32(chunk, crc32_result)
    return crc32_result & 0xFFFFFFFF

calculate_crc32('cat.jpg')