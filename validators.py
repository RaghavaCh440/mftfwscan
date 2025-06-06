from typing import List
from mftfwscan.models import FirewallRule

def detect_misconfig(rules: List[FirewallRule]) -> List[str]:
    issues = []
    for rule in rules:
        if rule.port in (20, 21) and rule.direction == "inbound":
            issues.append(f"[!] FTP port {rule.port} open without TLS")
        if rule.port > 1024:
            issues.append(f"[!] High port {rule.port} open — check use case")
        if rule.source == "0.0.0.0/0":
            issues.append(f"[!] Rule open to all IPs for port {rule.port}")
    return issues

