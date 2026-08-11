import os
import glob
import subprocess

from detector import run_detector



# ==== CONFIG ====
INPUT_DIR = "input_cert"
OUTPUT_PEM = os.path.join(INPUT_DIR, "converted.pem")

# Baseline (CHỌN 1 TRONG 2 FILE)
BASELINE_CERT = "certs/google.pem"
# BASELINE_CERT = "certs/google_current.pem"  # nếu em muốn baseline mới


def find_user_cert():
    """Tìm file .der người dùng đặt vào input_cert/"""
    files = glob.glob(os.path.join(INPUT_DIR, "*.der"))
    if not files:
        print("❌ Không tìm thấy file .der trong input_cert/")
        return None
    if len(files) > 1:
        print("❌ Chỉ được để 1 file .der trong input_cert/. Đang có:", files)
        return None
    return files[0]


def convert_to_pem(input_der):
    """Chuyển file DER sang PEM dùng openssl"""
    print("🔄 Đang chuyển đổi chứng chỉ sang PEM...")

    cmd = [
        "openssl", "x509",
        "-in", input_der,
        "-inform", "DER",
        "-out", OUTPUT_PEM,
        "-outform", "PEM"
    ]

    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print("❌ Lỗi khi chuyển đổi sang PEM:", e)
        return None

    return OUTPUT_PEM


def print_conclusion(is_suspicious, risk):
    print("\n==============================================")
    print("🔍 KẾT LUẬN:")

    if is_suspicious:
        print("⚠️  Chứng chỉ có dấu hiệu **BẤT THƯỜNG** – KHÔNG AN TOÀN.")
        print(f"🔺 Mức độ rủi ro: {risk}")
    else:
        print("🟢 Chứng chỉ **ỔN ĐỊNH – AN TOÀN**.")
        print(f"🔹 Risk Score: {risk}")

    print("==============================================\n")


def main():
    print("=== MITM Detector – Kiểm Tra Tự Động 1 Bước ===\n")

    # 1. Tìm file DER của người dùng
    user_file = find_user_cert()
    if not user_file:
        return

    print(f"📌 Đã tìm thấy file người dùng: {user_file}")

    # 2. Convert sang PEM
    pem_file = convert_to_pem(user_file)
    if not pem_file:
        return

    print(f"📄 File PEM để phân tích: {pem_file}")
    print("🔎 Đang kiểm tra chứng chỉ...")

    # 3. Chạy Detector
    verdict = run_detector(BASELINE_CERT, pem_file)

    # 4. In kết luận
    print_conclusion(verdict["suspicious"], verdict["risk_score"])


if __name__ == "__main__":
    main()
