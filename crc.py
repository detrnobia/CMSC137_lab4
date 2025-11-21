import random

FUNCTION = 0b1011
CORRUPTION_CHANCE = 0.10
ERROR_TOKEN = "__CRC_ERROR__"


def computeCRC(data: bytes, init=0):
    crc = init & 0b111
    for b in data:
        for i in range(8):
            bit = (b >> (7 - i)) & 1
            top = (crc >> 2) & 1
            crc = ((crc << 1) & 0b111) | bit
            if top:
                crc ^= (FUNCTION & 0b111)
    return crc & 0b111 


def randomCorrupt(packet: bytes, text: str):
    if text == ERROR_TOKEN:
        return packet

    if random.random() < CORRUPTION_CHANCE and len(packet) > 0:
        idx = random.randrange(len(packet))
        bit = 1 << random.randrange(8)
        corrupted = bytearray(packet)
        corrupted[idx] ^= bit
        return bytes(corrupted)

    return packet


def makePacket(text: str):
    payload = text.encode("utf-8")
    crc = computeCRC(payload)
    packet = payload + bytes([crc])
    return randomCorrupt(packet, text)


def verifyPacket(packet: bytes):
    if len(packet) == 0:
        return False, ""

    data = packet[:-1]
    recv_crc = packet[-1]
    calc_crc = computeCRC(data)

    try:
        text = data.decode("utf-8", errors="replace")
    except:
        text = ""

    return (calc_crc == recv_crc), text
