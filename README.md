```text
███╗   ██╗ ██████╗  ██████╗████████╗██╗███████╗
████╗  ██║██╔═══██╗██╔════╝╚══██╔══╝██║██╔════╝
██╔██╗ ██║██║   ██║██║        ██║   ██║███████╗
██║╚██╗██║██║   ██║██║        ██║   ██║╚════██║
██║ ╚████║╚██████╔╝╚██████╗   ██║   ██║███████║
╚═╝  ╚═══╝ ╚═════╝  ╚═════╝   ╚═╝   ╚═╝╚══════╝

# Noctis 
Noctis is a powerful, CLI-based network throttling tool. It uses ARP spoofing and Linux Traffic Control (`tc`) to precisely limit the bandwidth of specific devices on your local network.

## Features
* **Per-Device Limits:** Set different bandwidth limits (e.g., 500kbps, 2mbps) for individual targets.
* **Smart All:** Automatically excludes your own IP and the Router IP when selecting all devices.
* **Instant Throttling:** Utilizes `conntrack` to flush connections, applying limits immediately.
* **Live Monitor:** A clean, flicker-free terminal UI (built with Rich) to monitor traffic and dropped packets in real-time.

## Prerequisites
* Linux Operating System
* Python 3
* Root (`sudo`) privileges
* `conntrack` (optional, but highly recommended for instant throttling)

## Installation
Open your terminal and run the following commands sequentially:
1. Clone this repository:
   ```bash
   git clone https://github.com/Fathxs/Noctis.git

2. Navigate to the folder:
   '''bash
   cd Noctis

3. make this installer executable and run it:
   '''bash
   chmod +x install.sh
   sudo ./install.sh

## Usage
After the installation is complete, you can launch the application from any terminal by simply typing:
   '''bash
   noctis



Disclaimer
This tool is intended for educational and authorized network administration purposes only. Do not use this on networks you do not own or have explicit permission to manage.