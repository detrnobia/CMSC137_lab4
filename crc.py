# crc.py
# CRC-8 (polynomial 0x07) implementation for bytes

def compute_crc8(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    """
    Compute CRC-8 over the given bytes.
    Default polynomial: 0x07 (x^8 + x^2 + x + 1)
    Returns integer 0-255
    """
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) & 0xFF) ^ poly
            else:
                crc = (crc << 1) & 0xFF
    return crc

def make_packet(payload_text: str) -> bytes:
    """
    Create payload bytes (utf-8) + crc byte appended.
    Returns the bytes to be placed after length prefix.
    """
    payload = payload_text.encode('utf-8')
    crc = compute_crc8(payload)
    return payload + bytes([crc])

def verify_and_extract(packet: bytes) -> tuple[bool, str]:
    """
    Given payload+crc bytes, verify CRC and return (valid, text).
    If not valid, text contains the decoded payload (best effort) or ''.
    """
    if len(packet) == 0:
        return False, ''
    data = packet[:-1]
    recv_crc = packet[-1]
    calc_crc = compute_crc8(data)
    try:
        text = data.decode('utf-8', errors='replace')
    except:
        text = ''
    return (calc_crc == recv_crc, text)
