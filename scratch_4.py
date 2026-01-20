import sys
import os
from scapy.all import IP, TCP, Raw, send, wrpcap, Ether, RandShort

# --- Configuration ---
# Source IP address (from $EXTERNAL_NET in Snort rule terms)
src_ip = "192.168.1.100"
# Destination IP address (from $HOME_NET in Snort rule terms, your target server)
dst_ip = "192.168.1.1" # Change this to your target server's IP
# Source port (random ephemeral port)
src_port = RandShort()
# Destination port (HTTP port, e.g., 80)
dst_port = 80 # Change this if your HTTP server uses a different port

# The malicious URI payload designed to trigger the Snort rule
# Rule: pcre:"/union\s+(all\s+)?select\s+/Ui"
# %20 is URL-encoded space, which matches \s+
# The payload is placed in the GET request URI.
malicious_uri = b"/search?id=1%20union  all  select  user,password%20from%20users--"

# HTTP GET request body
# Using HTTP/1.0 for simplicity for raw packet crafting, but HTTP/1.1 is also fine.
http_request = b"GET " + malicious_uri + b" HTTP/1.0\r\nHost: " + dst_ip.encode() + b"\r\nUser-Agent: SnortTriggerScapy\r\nAccept: */*\r\n\r\n"

# Output PCAP file name
output_pcap_file = "C://Users//RohithRonanki//Desktop//snort_httpuri_sqli_trigger.pcap"

# --- Script Logic ---
def create_and_send_sqli_pcap():
    print(f"[*] Crafting packets to trigger Snort rule...")
    print(f"[*] Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}")
    print(f"[*] Malicious URI: {malicious_uri.decode()}")

    packets = []

    # 1. TCP 3-way Handshake (SYN)
    # Simulate a client initiating connection
    # Random initial sequence number
    initial_seq = 1000
    syn_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=initial_seq)
    packets.append(syn_packet)
    print("[+] Sent SYN packet.")

    # 2. TCP 3-way Handshake (SYN-ACK - simulated from server)
    # Acknowledge client's SYN, and send server's SYN
    # This requires predicting what the server would send.
    # In a real scenario, this would be a received packet.
    # For a PCAP, we just add it to simulate the established flow.
    synack_packet = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=initial_seq + 1)
    packets.append(synack_packet)
    print("[+] Simulated SYN-ACK packet.")

    # 3. TCP 3-way Handshake (ACK - client acknowledging server's SYN)
    # Finalize the 3-way handshake to establish the connection
    ack_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=initial_seq + 1, ack=2000 + 1)
    packets.append(ack_packet)
    print("[+] Sent ACK packet (connection established).")

    # 4. HTTP GET Request (with malicious URI)
    # Now send the actual HTTP request on the established connection
    # Increment sequence number by length of previous data (ACK has no data, so it's just previous_seq + 1)
    # The Raw layer carries the HTTP request bytes
    http_get_packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", seq=initial_seq + 1, ack=2000 + 1)/Raw(load=http_request)
    packets.append(http_get_packet)
    print("[+] Sent HTTP GET request packet.")

    # Save all packets to a PCAP file
    try:
        wrpcap(output_pcap_file, packets)
        print(f"\n[+] Successfully saved {len(packets)} packets to {output_pcap_file}")
        print(f"[*] You can now use this PCAP file with Snort for testing (e.g., 'snort -r {output_pcap_file} -c /etc/snort/snort.conf -A console')")
    except Exception as e:
        print(f"[-] Error saving PCAP file: {e}")

if __name__ == "__main__":
    # Check if running with appropriate privileges
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'): # Unix-like systems (Linux, macOS)
        if os.geteuid() != 0:
            print("[-] This script requires root/administrator privileges to send raw packets.")
            print("[-] Please run with sudo (e.g., 'sudo python generate_sqli_pcap.py')")
            sys.exit(1)
    elif sys.platform.startswith('win32'): # Windows
        print("[!] On Windows, ensure you are running this script from an Administrator Command Prompt or PowerShell.")
        print("[!] Raw packet sending typically requires elevated privileges.")
    else:
        print("[!] Unknown operating system. Please ensure you have the necessary privileges to send raw packets.")

    create_and_send_sqli_pcap()

