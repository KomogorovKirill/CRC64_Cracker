#!/usr/bin/env python3
# -*- coding utf-8 -*-

import sys

polynomial = 0xC96C5795D7870F42
table_crc = []

def getTable():
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= polynomial
            else:
                crc >>= 1
        table_crc.append(crc)

def crc64(s, crc = 0):
    for c in s:
        crc = table_crc[(crc & 0xFF) ^ ord(c)] ^ (crc >> 8) & 0xFFFFFFFFFFFFFFFF
    return crc


def forge_crc64(forge, header):
    table_reverse = []
    for i in range(256):
        table_reverse.append(0)
    for i in range(256):
        table_reverse[crc64(chr(i)) >> 56] = crc64(chr(i))

    prev_crc = forge
    rev_crc = []

    for i in range(8):
        high_bits = prev_crc >> 56
        prev_crc ^= table_reverse[high_bits]

        prev_crc <<= 8
        rev_crc.append(high_bits)

    result = ''
    header_crc = crc64(header)
    cur_high_bits = header_crc & 0xFF

    for rev_byte in rev_crc[::-1]:
        recovered = table_crc.index(table_reverse[rev_byte]) ^ cur_high_bits
        cur_high_bits = crc64(result + chr(recovered), header_crc) & 0xFF
        result += chr(recovered)
    result = header + result
    print("String(hex): 0x", end = "")
    for c in result:
        print(str(hex(ord(c)))[2::], end="")
    print("\nCRC64:       " + hex(crc64(result)))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Using: {sys.argv[0]} <crc64_sum> [prefix]")
        exit(1)
    header = ""
    getTable()
    if len(sys.argv) == 3:
        header = sys.argv[2]
    try:
        forge = int(sys.argv[1])
    except:
        forge = int(sys.argv[1], 16)
    forge_crc64(forge, header)
