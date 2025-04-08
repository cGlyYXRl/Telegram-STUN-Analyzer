# 🔍 Telegram STUN Analyzer 

A Python tool to detect IP leaks in Telegram calls by analyzing STUN protocol traffic.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Security-Tool-red)

## 🚀 Features

- 🕵️‍♂️ Captures STUN packets from Telegram calls
- 📡 Extracts peer IP addresses from XOR-MAPPED-ADDRESS
- 🌍 Performs WHOIS lookups for geolocation
- 🛡️ Filters out Telegram's official servers
- 📊 Detailed reporting with color-coded output
- 🔧 Configurable packet capture settings

## 📦 Installation

### Prerequisites
- Python 3.8+
- Wireshark/Tshark
- Root/admin privileges (for packet capture)

```bash
# Install dependencies
pip install pyshark requests netifaces colorama

# Verify tshark is installed
sudo apt install tshark  # Linux
brew install wireshark   # macOS

🛠️ Usage

python telegram_stun_analyzer.py [-h] [-i INTERFACE] [-c COUNT] [-v] [-t TIMEOUT] [-o OUTPUT]

Options:
Flag	Description
-i	Network interface (default: auto-select)
-c	Packet count to capture (default: 100)
-v	Verbose mode (show all packets)
-t	Capture timeout in seconds (default: 60)
-o	Save results to file
📝 Example Output

[+] 🎯 Found XOR-MAPPED-ADDRESS: 123.45.67.89
[+] 🌍 WHOIS Information:
    📍 Country: United States
    🏢 ISP: Comcast Cable
    🏙️ City: New York
    📶 AS: AS7922 Comcast Cable Communications, LLC

⚠️ Security Considerations

    This tool reveals IP addresses that Telegram may expose during calls

    Always get permission before testing on networks

    Recommended protections:

        🔐 Disable P2P in Telegram settings

        🌐 Use a VPN during calls

        🚫 Avoid calls on public WiFi

🤝 Contributing

    Fork the project

    Create your feature branch (git checkout -b feature/AmazingFeature)

    Commit your changes (git commit -m 'Add some amazing feature')

    Push to the branch (git push origin feature/AmazingFeature)

    Open a Pull Request

📜 License

Distributed under the MIT License. See LICENSE for more information.
