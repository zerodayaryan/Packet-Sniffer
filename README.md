# Packet Sniffer

A simple packet sniffer built with Python as part of my **Networking and Cybersecurity** learning journey. This project is currently under development, and I will continue adding new features and protocol support as I learn more about networking and cybersecurity.

> **Status:** 🚧 Under Development

## Features

- Capture network packets using **Scapy**
- Parse IPv4 and IPv6 packets
- Export captured packet information to a JSON file
- Modular codebase designed for future expansion

## Requirements

Before running the project, make sure you have the following installed:

- Python 3.x
- Scapy
- argparse (included in Python's standard library)

Install Scapy using pip:

```bash
pip install scapy
```

## Limitations

This project is still in development, and there are a few known limitations:

1. **Packet Loss During Capture**
   - Some packets may be dropped between the capturing and parsing stages.
   - This can likely be resolved by implementing multithreading.
   - I plan to add this feature in the future after learning more about threading.

2. **Limited Protocol Support**
   - Currently, the sniffer only processes **IPv4** and **IPv6** packets.
   - Future versions will include support for protocols such as:
     - ARP
     - DNS
     - UDP
     - TCP
     - ICMP
     - and more.

3. **Output Format**
   - At the moment, captured packets are only saved to a **JSON** file.
   - A future update will include a **live terminal dashboard** for real-time packet monitoring.

## Future Plans

- Multithreaded packet capture
- Support for additional network protocols
- Live terminal dashboard
- Better filtering options
- Improved packet analysis
- Performance optimizations

## Disclaimer

> **This project is intended strictly for educational purposes.**
>
> Use this tool **only on networks and devices that you own or have explicit permission to monitor.** Unauthorized packet sniffing may violate laws, regulations, or network policies. The author is not responsible for any misuse of this project.

## License

This project is open for learning and educational purposes. Feel free to explore the code, learn from it, and contribute improvements.
```
