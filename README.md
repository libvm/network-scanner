# Description
This project provides a simple GUI for scanning open ports on a target host and gathering basic host information.

# Usage
Run the script:
```bash
./main.py
```
1. In the "Target Hostname" field, enter the hostname or IP address of the target.
2. Enter the start and end ports in the "Start Port" and "End Port" fields. The port range cannot exceed 1000 ports due to limitations in the code.
3. Click the "Scan Ports" button to start scanning for open ports in the specified range.
4. Click the "Scan Host Info" button to retrieve basic information about the host.

# Dependencies
• Scapy
• Requests
