import binascii
from cryptography import x509
from cryptography.hazmat.primitives import serialization

DER_FILE = "mitm_cert_auto.der"
PEM_FILE = "mitm_cert_auto.pem"


def extract_cert_from_raw(raw_bytes: bytes) -> bytes:
    """
    Tìm certificate DER đầu tiên trong dữ liệu raw.
    """
    hex_data = raw_bytes.hex()

    for i in range(0, len(hex_data) - 8, 2):
        if hex_data[i:i+4] == "3082":
            length_hex = hex_data[i+4:i+8]
            try:
                length = int(length_hex, 16)
            except ValueError:
                continue

            total_len = (length + 4) * 2

            if i + total_len > len(hex_data):
                continue

            der_hex = hex_data[i:i+total_len]
            return binascii.unhexlify(der_hex)

    raise ValueError("Không tìm thấy certificate DER trong dữ liệu raw")


def main():
    with open(DER_FILE, "rb") as f:
        raw = f.read()

    der_cert = extract_cert_from_raw(raw)

    cert = x509.load_der_x509_certificate(der_cert)

    with open(PEM_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✔ Đã convert DER → PEM (MITM)")
    print("  Input raw :", DER_FILE)
    print("  Output PEM:", PEM_FILE)


if __name__ == "__main__":
    main()
