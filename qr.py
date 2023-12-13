#!/home/isaiah/Development/python/cable-test/env/bin/python3
from io import BytesIO
import struct
import sys
import time

import qrcode
import qrcode.image.svg


def generate_qr_code_as_svg(identity_public_key, qr_secret) -> bytes:
    cbor_data = _encode_qr_contents(identity_public_key, qr_secret)
    qr_data =  "FIDO:/" + _digit_encode(cbor_data)
    img = qrcode.make(qr_data, image_factory=qrcode.image.svg.SvgImage)
    return img.to_string()


def _encode_qr_contents(identity_public_key, qr_secret):
    num_map_elements = 6
    assigned_tunnel_domains = 2
    data = []
    data.append(0xa0 + num_map_elements)  # Map, 6 elements
    data.append(0)  # key 0, identity public key
    # _log(data)
    data.extend([0b010_11000, 33])  # 33 bytes
    data.extend(identity_public_key)
    data.append(1)  # key 1, qr secret
    data.append(0b010_10000)  # 16 bytes
    data.extend(qr_secret)
    data.append(2)  # key 2, tunnel domains length
    data.append(assigned_tunnel_domains)
    data.append(3)  # key 3, current time
    data.append(0b000_11010)  # 64-bit int
    data.extend(int(time.time()).to_bytes(4))
    data.append(4)  # key 4, supports state-assisted transactions
    data.append(0b111_10100)  # False
    # _log(data)
    data.append(5)  # key 5, operation hint
    data.extend([0b011_00010, int.from_bytes(b'm'), int.from_bytes(b'c')])
    # _log(data)
    # with open('/tmp/cbor.bin', 'wb') as f:
    #     f.write(bytes(data))
    return data


def _digit_encode(data):
    CHUNK_SIZE = 7
    CHUNK_DIGITS = 17
    ZEROS = "00000000000000000"

    ret = ""
    d = data
    while len(d) >= CHUNK_SIZE:
        chunk = bytes(d[:CHUNK_SIZE] + [0])
        v = struct.unpack("<Q", chunk)[0]
        ret += f"{v:017}"
        d = d[CHUNK_SIZE:]

    if len(d) != 0:
        # partialChunkDigits is the number of digits needed to encode
        # each length of trailing data from 6 bytes down to zero. I.e.
        # it’s 15, 13, 10, 8, 5, 3, 0 written in hex.
        # PARTIAL_CHUNK_DIGITS = 0x0fda8530
        # digits = 15 & (PARTIAL_CHUNK_DIGITS >> (4 * len(d)))
        # print(d)
        digits = [0, 3, 5, 8, 10, 13, 15][len(d)]
        # print(digits)
        chunk = bytes(d + [0]*(8 - len(d)) )
        v = str(struct.unpack("<Q", chunk)[0])
        # print(v)
        digits-len(v)
        ret += ZEROS[:digits-len(v)]
        ret += v

    return ret


def main():
    key_file = sys.argv[1]
    data_file = sys.argv[2]
    key = open(key_file, 'rb').read()
    data = open(data_file, 'rb').read()
    plaintext = trial_decrypt(eid_key, data)
    (nonce, routing_id, encoded_tunnel_server_domain) = unpack_decrypted_advert(plaintext)
    # domain = decode_tunnel_server_domain(encoded_tunnel_server_domain)
    domain = decode_tunnel_server_domain(256)
    # print(domain)


def _log(data):
    print("".join([f"{x:02x}" for x in data]))

if __name__ == '__main__':
    main()