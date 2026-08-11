import binascii
from cryptography import x509
from cryptography.hazmat.primitives import serialization

DER_FILE = "baseline_cert.der"
PEM_FILE = "baseline_cert.pem"


def extract_cert_from_raw(raw_bytes: bytes) -> bytes:
    """
    Trong raw_bytes (có thể là TLS handshake), tìm certificate DER đầu tiên.
    Certificate DER bắt đầu bằng pattern: 30 82 xx xx (SEQUENCE + length 2 bytes)
    """
    hex_data = raw_bytes.hex()

    for i in range(0, len(hex_data) - 8, 2):
        if hex_data[i:i+4] == "3082":
            length_hex = hex_data[i+4:i+8]
            try:
                length = int(length_hex, 16)
            except ValueError:
                continue

            total_len = (length + 4) * 2  # 4 bytes header 30 82 xx xx

            if i + total_len > len(hex_data):
                # length báo lớn hơn phần còn lại -> không hợp lệ
                continue

            der_hex = hex_data[i:i+total_len]
            return binascii.unhexlify(der_hex)

    raise ValueError("Không tìm thấy certificate DER trong dữ liệu raw")


def main():
    # Đọc dữ liệu raw từ file .der (thực chất là TLS handshake chunk)
    with open(DER_FILE, "rb") as f:
        raw = f.read()

    # Cắt ra phần certificate DER chuẩn
    der_cert = extract_cert_from_raw(raw)

    # Convert sang đối tượng x509
    cert = x509.load_der_x509_certificate(der_cert)

    # Ghi ra file PEM
    with open(PEM_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✔ Đã convert DER → PEM (baseline)")
    print("  Input raw :", DER_FILE)
    print("  Output PEM:", PEM_FILE)


if __name__ == "__main__":
    main()
