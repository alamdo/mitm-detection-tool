import argparse
from analyzer import load_certificate
from comparator import compare_certs
from rule_engine import evaluate_mitm



def print_result(result, compare_result=None):
    print("\n=== MITM Certificate Detector ===\n")

    print(f"Verdict       : {result['verdict']}")
    print(f"Risk Score    : {result['risk_score']}")
    print(f"Suspicious    : {result['suspicious']}")

    print("\nTriggered Rules:")
    if not result["rules_triggered"]:
        print(" - None (SAFE)")
    else:
        for r in result["rules_triggered"]:
            print(f" - {r}")

    # Dùng compare_result truyền vào (từ run_detector),
    # nếu không có thì fallback sang result["compare"]
    if compare_result is None:
        compare = result.get("compare", {})
    else:
        compare = compare_result

    print("\n=== Compare Details ===")
    for k, v in compare.items():
        print(f"{k:20}: {v}")

def run_detector(baseline_path: str, test_path: str):

    compare_result = compare_certs(baseline_path, test_path)
    result = evaluate_mitm(baseline_path, test_path)

    print_result(result, compare_result)

    return result




def main():
    parser = argparse.ArgumentParser(description="MITM Detector CLI")
    parser.add_argument("--baseline", required=True, help="Path to baseline certificate")
    parser.add_argument("--test", required=True, help="Path to test certificate")

    args = parser.parse_args()

    result = evaluate_mitm(args.baseline, args.test)
    print_result(result)


if __name__ == "__main__":
    main()
