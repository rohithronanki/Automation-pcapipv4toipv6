from scapy.all import Ether, IP, TCP, Raw, wrpcap
import os
import random
import collections

def create_sql_injection_trigger_pcap(output_pcap_path="sql_injection_union_select.pcap"):
    """
    Crafts a PCAP file to trigger the Snort rule for 'union select' SQL injection.
    It includes a full TCP 3-way handshake followed by an HTTP GET request
    with the specified URL-encoded payload in the URI.
    """

    # --- Packet Parameters ---
    src_ip = "192.168.1.100"  # Client IP
    dst_ip = "192.168.1.1"    # Server IP (target of the injection)
    dst_port = 80             # HTTP port
    src_port = random.randint(49152, 65535) # Client's ephemeral source port

    # --- HTTP GET Request URI ---
    # The Snort rule explicitly mentions "http_uri" and the payload should be URL-encoded.
    # The user provided: http://<target>/union%20select%201+1
    # We will use this exact URI path.
    malicious_uri_path = b"/union%20select%201+1" # Already URL-encoded as a byte string

    # --- Construct HTTP GET Request ---
    # HTTP Request Line: GET <URI> HTTP/1.1\r\n
    request_line = b"GET " + malicious_uri_path + b" HTTP/1.1\r\n"

    # Standard HTTP Headers
    headers = collections.OrderedDict([
        (b"Host", b"example.com"), # Or use the target IP directly, e.g., b"192.168.1.1"
        (b"User-Agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
        (b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
        (b"Accept-Language", b"en-US,en;q=0.5"),
        (b"Connection", b"close") # Close connection after this request
    ])

    header_lines = b""
    for header_name, header_value in headers.items():
        header_lines += header_name + b": " + header_value + b"\r\n"

    # Full raw HTTP request: Request Line + Headers + CRLF (blank line)
    http_raw_request = request_line + header_lines + b"\r\n"

    # --- Crafting the Packets for a Full TCP Session (3-Way Handshake) ---
    packets_to_write = []

    # Initial sequence numbers for client and server
    client_isn = random.randint(1000, 65535)
    server_isn = random.randint(1000, 65535)

    # 1. SYN packet (Client -> Server)
    syn_pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
        dport=dst_port, sport=src_port, flags="S", seq=client_isn
    )
    packets_to_write.append(syn_pkt)

    # 2. SYN-ACK packet (Server -> Client) - Simulated Response
    syn_ack_pkt = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(
        dport=src_port, sport=dst_port, flags="SA", seq=server_isn, ack=client_isn + 1
    )
    packets_to_write.append(syn_ack_pkt)

    # 3. ACK packet (Client -> Server) - Client acknowledges SYN-ACK
    # This completes the 3-way handshake, fulfilling 'flow:established'
    ack_pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
        dport=dst_port, sport=src_port, flags="A", seq=client_isn + 1, ack=server_isn + 1
    )
    packets_to_write.append(ack_pkt)

    # 4. HTTP GET Data Packet (Client -> Server) - Now with established connection
    # Flags="PA" (Push, Acknowledge) is typical for a data-carrying segment ending a request.
    data_pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
        dport=dst_port, sport=src_port, flags="PA", seq=client_isn + 1, ack=server_isn + 1
    ) / Raw(load=http_raw_request) # The full HTTP request as raw payload
    packets_to_write.append(data_pkt)

    # --- Save to PCAP ---
    try:
        wrpcap(output_pcap_path, packets_to_write)
        print(f"PCAP '{output_pcap_path}' created successfully.")
        print(f"  Simulated Client: {src_ip}:{src_port}")
        print(f"  Simulated Server: {dst_ip}:{dst_port}")
        print(f"  Injected URI: {malicious_uri_path.decode()}")
        print("\n  This PCAP includes a full TCP handshake and an HTTP GET request.")
        print("  You can open this PCAP in Wireshark to verify the packet structure and payload.")
    except Exception as e:
        print(f"Error saving PCAP: {e}")

# --- Execute the function ---
if __name__ == "__main__":
    # Define your desired output PCAP file path
    output_file = "C://Users//RohithRonanki//Desktop//snort_sql_injection_trigger.pcap" # <-- CUSTOMIZE THIS PATH
    os.makedirs(os.path.dirname(output_file), exist_ok=True) # Ensure output directory exists

    create_sql_injection_trigger_pcap(output_file)

    print("\n--- To test this PCAP against Snort: ---")
    print("1. Ensure Snort is running and configured to inspect HTTP traffic.")
    print("2. Make sure the rule with SID 2022102010 is enabled in your Snort ruleset.")
    print(f"3. Use a tool like 'tcpreplay' to send the PCAP to your Snort monitoring interface:")
    print(f"   sudo tcpreplay --intf=<your_snort_interface> {output_file}")
    print("   Replace <your_snort_interface> with the actual name (e.g., eth0, en0).")
    print("4. Check Snort's alerts (e.g., in /var/log/snort/alert or your SIEM).")