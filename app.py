import crypto
import qr


def main():
    (identity_key, identity_public_key, qr_secret) = crypto.generate_keys()
    show_qr_code(identity_public_key, qr_secret)


def show_qr_code(identity_public_key, qr_secret):
    qr_code = qr.generate_qr_code(identity_public_key, qr_secret)


def _log(data):
    print("".join([f"{b:02x}" for b in data]))