from dataclasses import dataclass
import ipaddress

@dataclass
class FirewallRule:
    source: str
    destination: str
    port: int
    protocol: str
    direction: str

    def validate(self):
        ipaddress.ip_network(self.source)
        ipaddress.ip_address(self.destination)

