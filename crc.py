# crc.py
# --------------------------------------------------------------------
# CRC-3 using G(x) = x^3 + x + 1
# Includes 10% corruption simulation for NORMAL CHAT MESSAGES ONLY.
# __CRC_ERROR__ packets are NEVER corrupted to prevent protocol stalls.
# --------------------------------------------------------------------

import random

POLY = 0b1011
CORRUPTION_CHANCE = 0.10
ERROR_TOKEN = "__CRC_ERROR__"


def compute_crc3(data: bytes, init=0):
    crc = init & 0b111
    for b in data:
        for i in range(8):
            bit = (b >> (7 - i)) & 1
            top = (crc >> 2) & 1
            crc = ((crc << 1) & 0b111) | bit
            if top:
                crc ^= (POLY & 0b111)
    return crc & 0b111


def maybe_corrupt(packet: bytes, text: str) -> bytes:
    """Corrupt only NORMAL MESSAGES. NEVER corrupt ERROR_TOKEN."""
    if text == ERROR_TOKEN:
        return packet  # NEVER corrupt control packets

    if random.random() < CORRUPTION_CHANCE and len(packet) > 0:
        idx = random.randrange(len(packet))
        bit = 1 << random.randrange(8)
        corrupted = bytearray(packet)
        corrupted[idx] ^= bit
        return bytes(corrupted)

    return packet


def make_packet(text: str) -> bytes:
    payload = text.encode("utf-8")
    crc = compute_crc3(payload)
    packet = payload + bytes([crc])
    return maybe_corrupt(packet, text)


def verify_and_extract(packet: bytes):
    if len(packet) == 0:
        return False, ""

    data = packet[:-1]
    recv_crc = packet[-1]
    calc_crc = compute_crc3(data)

    try:
        text = data.decode("utf-8", errors="replace")
    except:
        text = ""

    return (calc_crc == recv_crc), text
