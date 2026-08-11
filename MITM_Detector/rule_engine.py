from comparator import compare_certs

def evaluate_mitm(baseline_path: str, test_path: str):
    """
    Rule Engine phát hiện MITM dựa trên kết quả so sánh chứng chỉ.

    Output:
        - suspicious: True/False (có đáng nghi không)
        - risk_score: [0.0 ; 1.0] mức độ nguy cơ MITM
        - rules_triggered: danh sách các rule bị vi phạm
        - compare: kết quả raw từ comparator
        - verdict: SAFE | SUSPICIOUS | LIKELY_MITM
    """

    compare_result = compare_certs(baseline_path, test_path)

    result = {
        "suspicious": False,
        "risk_score": 0.0,
        "rules_triggered": [],
        "compare": compare_result,
        "verdict": "SAFE"
    }

    # === R001: Fingerprint mismatch (mạnh nhất) ===
    if compare_result["fingerprint_match"] is False:
        result["suspicious"] = True
        result["risk_score"] += 0.6
        result["rules_triggered"].append("R001_FINGERPRINT_MISMATCH")

    # === R002: Issuer khác nhau (khả năng dùng CA lạ / self-signed) ===
    if compare_result["issuer_match"] is False:
        result["suspicious"] = True
        result["risk_score"] += 0.2
        result["rules_triggered"].append("R002_ISSUER_MISMATCH")

    # === R003: SAN mismatch (không trùng domain nào) ===
    if compare_result["san_match"] is False:
        result["suspicious"] = True
        result["risk_score"] += 0.3
        result["rules_triggered"].append("R003_SAN_MISMATCH")

    # === R004: CN mismatch ===
    if compare_result["cn_match"] is False:
        result["suspicious"] = True
        result["risk_score"] += 0.2
        result["rules_triggered"].append("R004_CN_MISMATCH")

    # === R005: Validity không giao nhau (cert hết hạn / chưa có hiệu lực) ===
    if compare_result["validity_overlap"] is False:
        result["suspicious"] = True
        result["risk_score"] += 0.2
        result["rules_triggered"].append("R005_VALIDITY_PROBLEM")

    # Giới hạn risk_score tối đa 1.0
    if result["risk_score"] > 1.0:
        result["risk_score"] = 1.0

    # Đưa ra verdict theo risk_score
    if result["risk_score"] >= 0.7:
        result["verdict"] = "LIKELY_MITM"
    elif result["risk_score"] >= 0.3:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "SAFE"

    return result



# Đoạn test nhanh
if __name__ == "__main__":
    baseline = "certs/google.pem"      # cert thật
    test = "certs/fake_mitm.pem"       # cert giả MITM
    out = evaluate_mitm(baseline, test)
    print(out)
