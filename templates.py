from mftfwscan.models import FirewallRule

def export_iptables(rule: FirewallRule) -> str:
    return f"-A INPUT -p {rule.protocol.lower()} --dport {rule.port} -s {rule.source} -j ACCEPT"

def export_gcp(rule: FirewallRule) -> dict:
    return {
        "name": f"allow-{rule.protocol.lower()}-{rule.port}",
        "allowed": [{"IPProtocol": rule.protocol.lower(), "ports": [str(rule.port)]}],
        "sourceRanges": [rule.source],
        "direction": rule.direction.upper()
    }

def export_aws(rule: FirewallRule) -> dict:
    return {
        "IpProtocol": rule.protocol.lower(),
        "FromPort": rule.port,
        "ToPort": rule.port,
        "CidrIp": rule.source
    }
