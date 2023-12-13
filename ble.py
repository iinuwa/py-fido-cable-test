import asyncio
import threading

from bleak import BleakScanner

import crypto

ASSIGNED_TUNNEL_SERVER_DOMAINS = ["cable.ua5v.com", "cable.auth.com"]

FIDO_CABLE_BLE_UUIDS = [
    "0000fff9-0000-1000-8000-00805f9b34fb",  # FIDO CTAP 2.2 standard UUID
    "0000fde2-0000-1000-8000-00805f9b34fb",  # Google's UUID
]

loop = None

def _start(start_event):
    global loop
    loop = asyncio.new_event_loop()
    start_event.set()
    loop.run_forever()
    
def init():
    start_event = threading.Event()
    th = threading.Thread(target=_start, args=(start_event,))
    th.start()
    start_event.wait()

def stop():
    loop.call_soon_threadsafe(loop.stop)


def detect_fido_advert(qr_secret, device, advert):
    try:
        for uuid in FIDO_CABLE_BLE_UUIDS:
            if ciphertext := advert.service_data.get(uuid):
                # print("".join([f"{x:02x}" for x in ciphertext]))
                plaintext = crypto.decrypt_ble_advertisement(qr_secret, ciphertext)
                if not _reserved_bits_are_zero(plaintext):
                    raise Exception("Reserved bits of plaintext are not set to zero")
                data = _unpack_advert(plaintext)
                return data
    except Exception as e:
        print("WARN: Detected FIDO caBLE advertisement, but could not decrypt", e.args)
        pass


async def _scan_adverts(qr_secret):
    # found_event = asyncio.Event()
    # discover_task = None
    async with BleakScanner(
        service_uuids=FIDO_CABLE_BLE_UUIDS,
        scanning_mode="active",
        # detection_callback=functools.partial(detect_fido_advert, qr_secret)
    ) as scanner:
        print("Scanning for FIDO2 caBLE BLE advertisements...")
        async for device, advert in scanner.advertisement_data():
            if data := detect_fido_advert(qr_secret, device, advert):
                return data


def await_advert(qr_secret, callback):
    fut = asyncio.run_coroutine_threadsafe(_scan_adverts(qr_secret), loop)
    fut.add_done_callback(callback)


def _reserved_bits_are_zero(data):
    return data[0] == 0


def _unpack_advert(plaintext):
    # reserved = plaintext[0]
    nonce = plaintext[1:11]
    routing_id = plaintext[11:14]
    encoded_tunnel_server_domain = int.from_bytes(plaintext[14:], byteorder='little')
    return (nonce, routing_id, encoded_tunnel_server_domain)


def _decode_tunnel_server_domain(encoded) -> str:
    if encoded < 256:
        if encoded >= len(ASSIGNED_TUNNEL_SERVER_DOMAINS):
            raise Exception("Invalid tunnel server domain number")
        return ASSIGNED_TUNNEL_SERVER_DOMAINS[encoded]
    sha_input = b'caBLEv2 tunnel server domain' + encoded.to_bytes(2, byteorder='little') + b'\x00'
    digest = hashlib.sha256(sha_input).digest()

    v = int.from_bytes(digest[:8], byteorder='little')
    tld_index = v & 3
    v = v >> 2

    domain = "cable."
    BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"
    while v != 0:
        domain += str(BASE32_CHARS[v & 31])
        v = v >> 5

    TLDS = [".com", ".org", ".net", ".info"]
    domain += TLDS[tld_index & 3]

    return domain