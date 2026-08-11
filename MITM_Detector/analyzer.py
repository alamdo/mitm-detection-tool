from cryptography import x509
from cryptography.hazmat.backends import default_backend

def load_certificate(cert_path: str):
    """
    Load một chứng chỉ X.509 từ file .pem
    Trả về object certificate của thư viện cryptography.
    """
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert


def get_subject_cn(cert):
    """
    Lấy Subject Common Name (CN)
    """
    subject = cert.subject
    cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return cn


def get_issuer_name(cert):
    """
    Lấy Issuer CN (CA cấp chứng chỉ)
    """
    issuer = cert.issuer
    cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return cn


def get_san(cert):
    """
    Lấy danh sách Subject Alternative Names (SAN)
    """
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
        return san
    except Exception:
        return []


def get_validity(cert):
    """
    Lấy thời gian hiệu lực (not_before, not_after)
    """
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    return not_before, not_after


def test_certificate():
    cert_path = "certs/google.pem"
    cert = load_certificate(cert_path)

    cn = get_subject_cn(cert)
    issuer = get_issuer_name(cert)
    san = get_san(cert)
    not_before, not_after = get_validity(cert)

    print("=== Certificate Analysis ===")
    print(f"Subject CN  : {cn}")
    print(f"Issuer CN   : {issuer}")
    print(f"SAN         : {san}")
    print(f"Not Before  : {not_before}")
    print(f"Not After   : {not_after}")


if __name__ == "__main__":
    print("Analyzer loaded successfully!")
    test_certificate()
