from typing import List
from mftfwscan.models import FirewallRule

MFT_PORTS = {
    "SFTP": 22,
    "FTPS": 990,
    "FTP_PASSIVE": (1024, 65535),
    "AS2": 4080,
}

def simulate_port_forwarding(service: str) -> List[FirewallRule]:
    port_info = MFT_PORTS.get(service.upper())
    rules = []

    if isinstance(port_info, tuple):
        for port in range(port_info[0], port_info[0] + 10):
            rules.append(FirewallRule(
                source="0.0.0.0/0",
                destination="192.168.1.10",
                port=port,
                protocol="TCP",
                direction="inbound"
            ))
    else:
        rules.append(FirewallRule(
            source="0.0.0.0/0",
            destination="192.168.1.10",
            port=port_info,
            protocol="TCP",
            direction="inbound"
        ))
    return rules
