from analyzer import (
    load_certificate,
    get_subject_cn,
    get_issuer_name,
    get_san,
    get_validity,
)



from cryptography.hazmat.primitives import hashes

def compare_certs(baseline_path: str, test_path: str):
    """
    So sánh cert chuẩn và cert nghi ngờ.
    Trả về dict chứa kết quả so sánh các trường quan trọng.
    """
    # Load certificates
    baseline = load_certificate(baseline_path)
    test = load_certificate(test_path)

    # Extract fields
    base_cn = get_subject_cn(baseline)
    test_cn = get_subject_cn(test)

    base_issuer = get_issuer_name(baseline)
    test_issuer = get_issuer_name(test)

    base_san = set(get_san(baseline))
    test_san = set(get_san(test))

    base_not_before, base_not_after = get_validity(baseline)
    test_not_before, test_not_after = get_validity(test)

    # Fingerprint for uniqueness
    base_fp = baseline.fingerprint(hashes.SHA256())
    test_fp = test.fingerprint(hashes.SHA256())

    result = {
        "cn_match": base_cn == test_cn,
        "issuer_match": base_issuer == test_issuer,
        "san_match": len(base_san.intersection(test_san)) > 0,
        "validity_overlap": not (test_not_after < base_not_before or test_not_before > base_not_after),
        "fingerprint_match": base_fp == test_fp
    }

    return result


# Test quick
if __name__ == "__main__":
    baseline = "certs/google.pem"
    test = "certs/google.pem"  # test same cert → all True
    print(compare_certs(baseline, test))
