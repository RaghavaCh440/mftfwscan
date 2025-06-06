import json
import argparse
from mftfwscan.core import simulate_port_forwarding
from mftfwscan.validators import detect_misconfig
from mftfwscan.templates import export_iptables, export_gcp, export_aws

def main():
    parser = argparse.ArgumentParser(description="MFT Firewall Rule Simulator")
    parser.add_argument("--service", required=True, help="Protocol to simulate (e.g., SFTP, FTPS, FTP_PASSIVE, AS2)")
    parser.add_argument("--export", choices=["iptables", "gcp", "aws"], default="iptables")
    args = parser.parse_args()

    rules = simulate_port_forwarding(args.service)
    issues = detect_misconfig(rules)

    print("\n[+] Simulated Rules:")
    for rule in rules:
        if args.export == "iptables":
            print(export_iptables(rule))
        elif args.export == "gcp":
            print(json.dumps(export_gcp(rule), indent=2))
        elif args.export == "aws":
            print(json.dumps(export_aws(rule), indent=2))

    print("\n[!] Potential Misconfigurations:")
    for issue in issues:
        print(issue)

if __name__ == "__main__":
    main()
