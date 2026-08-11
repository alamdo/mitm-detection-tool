import pyshark
import binascii
import re

PCAP_PATH = "pcap_mitm.pcap"    # 🔹 PCAP MITM
OUTPUT_DER = "mitm_cert_auto.der"   # 🔹 File DER MITM sẽ tạo

def find_der(hex_data: str) -> bytes | None:
    """
    Tìm cấu trúc certificate ASN.1 DER trong chuỗi hex của frame.
    """
    matches = re.finditer(r"3082[0-9a-fA-F]{4}", hex_data)

    for m in matches:
        start_byte_index = m.start() // 2
        length_hex = hex_data[m.start()+4:m.start()+8]
        length = int(length_hex, 16)
        total_length = length + 4
        der_hex = hex_data[m.start(): m.start() + total_length * 2]
        return binascii.unhexlify(der_hex)

    return None


def main():
    capture = pyshark.FileCapture(
        PCAP_PATH,
        display_filter="tls.handshake.type == 11",
        use_json=True,
        include_raw=True
    )

    print("Đang extract certificate MITM bằng phương pháp RAW từ file:", PCAP_PATH)

    for idx, packet in enumerate(capture, start=1):
        print(f"- Kiểm tra gói thứ {idx}...")

        try:
            raw_hex = packet.frame_raw.value.lower()
        except Exception:
            print("  ➜ Không đọc được raw frame, bỏ qua.")
            continue

        der = find_der(raw_hex)
        if der:
            with open(OUTPUT_DER, "wb") as f:
                f.write(der)

            print(f"✔ EXTRACT THÀNH CÔNG certificate MITM từ gói thứ {idx}")
            print(f"✔ Đã lưu file: {OUTPUT_DER}")
            break
        else:
            print("  ➜ Không tìm thấy certificate trong gói này, bỏ qua.")

    capture.close()
    print("Hoàn tất.")

if __name__ == "__main__":
    main()
