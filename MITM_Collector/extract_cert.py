import pyshark
import binascii
import re

PCAP_PATH = "pcap_baseline.pcap"   # PCAP nguồn
OUTPUT_DER = "baseline_cert.der"   # File cert dạng DER sẽ được tạo

def find_der(hex_data: str) -> bytes | None:
    """
    Tìm cấu trúc certificate ASN.1 DER trong chuỗi hex của frame.

    Certificate X.509 dạng DER bắt đầu bằng:
        30 82 xx xx ...
    - 0x30 : SEQUENCE
    - 0x82 : length 2 bytes
    - xx xx : độ dài phần còn lại
    """
    # Tìm pattern 30 82 XX XX (4 byte đầu)
    matches = re.finditer(r"3082[0-9a-fA-F]{4}", hex_data)

    for m in matches:
        # vị trí tính theo NIBBLE -> chia 2 ra index theo byte
        start_byte_index = m.start() // 2

        # lấy 2 byte length sau 30 82
        length_hex = hex_data[m.start()+4:m.start()+8]
        length = int(length_hex, 16)

        total_length = length + 4   # +4 vì 30 82 XX XX

        der_hex = hex_data[m.start(): m.start() + total_length * 2]
        return binascii.unhexlify(der_hex)

    return None


def main():
    capture = pyshark.FileCapture(
        PCAP_PATH,
        display_filter="tls.handshake.type == 11",
        use_json=True,      # bắt buộc nếu dùng include_raw
        include_raw=True    # để đọc frame_raw
    )

    print("Đang extract certificate bằng phương pháp RAW từ file:", PCAP_PATH)

    for idx, packet in enumerate(capture, start=1):
        print(f"- Kiểm tra gói thứ {idx}...")

        try:
            # frame_raw.value là chuỗi hex đầy đủ của frame
            raw_hex = packet.frame_raw.value.lower()
        except Exception:
            print("  ➜ Không đọc được raw frame, bỏ qua.")
            continue

        der = find_der(raw_hex)
        if der:
            with open(OUTPUT_DER, "wb") as f:
                f.write(der)

            print(f"✔ EXTRACT THÀNH CÔNG certificate từ gói thứ {idx}")
            print(f"✔ Đã lưu file: {OUTPUT_DER}")
            break
        else:
            print("  ➜ Không tìm thấy certificate trong gói này, bỏ qua.")

    capture.close()
    print("Hoàn tất.")

if __name__ == "__main__":
    main()
