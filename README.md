# Packet Sniffer Project

## Overview

This Packet Sniffer Project is designed to offer a robust tool for network analysis and educational purposes.
It captures and analyzes network traffic in real-time, providing insights into the data flowing through your network.
Developed with Python and using the Scapy library, this tool is built for simplicity and flexibility,
serving both beginners and experienced network analysts.

## Features

- **Real-time Packet Sniffing**: Captures TCP, UDP, and other protocol packets on your network.
- **Packet Logging**: Automatically aggregates packets and logs them into PCAP files, organized by timestamp for straightforward analysis.
- **Automatic Capture Termination**: Allows setting a maximum duration for packet capture to manage data volume and preserve system resources.
- **Cross-Platform Support**: Compatible with macOS, Linux, and Windows, offering versatile deployment options.

## Prerequisites

To get started with this packet sniffer, you'll need:

- Python 3.x installed on your machine.
- Administrative or root privileges for packet capture on your network interface.
- A preliminary understanding of network protocols and packet structures (beneficial, but not mandatory).

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://yourrepositorylink.com/packet-sniffer.git
   cd packet-sniffer

2. ## Create and Activate a Virtual Environment (Recommended)

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. ## Install Required Dependencies

   ```bash
   pip install -r requirements.txt

4. ## Usage

   Execute the 'main.py' script with the necessary permissions to start sniffing packets:
   ```bash
   sudo python3 src/main.py

This initiates the packet capture process,
logging the packets into the packet_logs directory in PCAP files, grouped by timestamp.
The capture session automatically concludes after a predefined duration (default is 5 minutes),
but this can be customized in the script settings.

## Configuration
Batch Size: Modify BATCH_SIZE in packet_processing.py to change the number of packets accumulated before logging.
Capture Duration: Adjust MAX_CAPTURE_DURATION in packet_processing.py to set your preferred maximum capture time.

## Contributing
Your contributions are welcome! Please consult CONTRIBUTING.md for details on how to contribute to this project.

## License
This project is licensed under the MIT License—see the LICENSE file for more information.

## Disclaimer
This tool is strictly for educational and network analysis purposes.
Ensure you have explicit permission to capture network traffic, adhering to legal and ethical standards.
