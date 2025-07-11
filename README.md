
[![PyPI Downloads](https://static.pepy.tech/badge/mftfwscan)](https://pepy.tech/project/mftfwscan)

# mftfwscan

`mftfwscan` is a specialized command-line toolkit designed to simulate, validate, and audit firewall and Network Address Translation (NAT) rules specifically tailored for Managed File Transfer (MFT) environments. In secure enterprise data flows, MFT protocols like SFTP, FTPS, AS2, and HTTPS typically require well-defined inbound and outbound port configurations, as well as NAT traversal setups to accommodate internal services behind firewalls or proxies. Misconfigured rules in these systems—such as open high ports, overly permissive source IPs, or missing TLS protections—can expose sensitive data or create compliance violations.

This tool enables system administrators, DevOps engineers, and security teams to programmatically define and simulate what a secure rule set should look like for a given MFT protocol, then audit real or proposed configurations for common misconfigurations. It outputs rule formats compatible with widely used firewall systems like iptables, Google Cloud Platform (GCP) firewall rules, and AWS Security Group policies. Furthermore, mftfwscan highlights potentially insecure practices such as "allow all" source ranges or unencrypted protocol ports, helping teams proactively harden their infrastructure.

By integrating MFT protocol awareness with static rule validation, mftfwscan fills a niche gap in firewall simulation tools—bringing protocol-specific insight into the traditionally generic firewall configuration space. This allows for both real-time validation during DevOps CI/CD workflows and offline auditing of legacy infrastructure policies.

## Features
- Simulate inbound port rules for SFTP, FTPS, AS2, and Passive FTP
- Identify potential misconfigurations like open high ports or unrestricted sources
- Export rules as iptables, GCP firewall, or AWS security group formats

## Installation

```bash
pip install .
```

## Usage

```bash
mftfwscan --service SFTP --export iptables
```

## Requirements
- Python 3.7+

---

## Example Output

```bash
$ mftfwscan --service SFTP --export iptables
-A INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j ACCEPT
[!] Rule open to all IPs for port 22
```


# == LICENSE (MIT) ==

MIT License

Copyright (c) 2025 Raghava Chellu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

