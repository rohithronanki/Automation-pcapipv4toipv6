from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6, UDP, TCP, DNS, DNSQR, DNSRR
import collections
import ipaddress
import random


def automate_ipv4_to_ipv6_fast_flux_conversion(input_pcap_path, output_pcap_path):
    """
    Automates the conversion of IPv4 fast flux related packets in a PCAP to IPv6.

    Args:
        input_pcap_path (str): Path to the input IPv4 PCAP file.
        output_pcap_path (str): Path to save the converted IPv6 PCAP file.
    """
    print(f"Loading PCAP from: {input_pcap_path}")
    try:
        packets = rdpcap(input_pcap_path)
    except FileNotFoundError:
        print(f"Error: Input PCAP file not found at {input_pcap_path}")
        return
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        return

    # --- Step 1: Identify Fast Flux Domains and IPs ---
    print("Step 1: Identifying fast flux domains and their associated IPv4 addresses...")
    domain_ip_ttls = collections.defaultdict(lambda: collections.defaultdict(list))
    # Threshold for a 'low' TTL indicating potential flux
    FLUX_TTL_THRESHOLD = 60  # seconds, typically fast flux uses very low TTLs (e.g., 60, 300)

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # DNS Response
            for ans_rr in pkt[DNS].an:
                if ans_rr.type == 1:  # A record (IPv4 address)
                    domain = ans_rr.rrname.decode('utf-8').strip('.')  # Decode and clean domain name
                    ipv4_addr = ans_rr.rdata
                    ttl = ans_rr.ttl
                    domain_ip_ttls[domain][ipv4_addr].append(ttl)

    flux_ipv4_addresses = set()
    flux_domains = set()

    for domain, ip_data in domain_ip_ttls.items():
        if len(ip_data) > 1:  # Domain resolves to multiple IPs
            low_ttl_ips_count = 0
            for ipv4_addr, ttls in ip_data.items():
                if any(t <= FLUX_TTL_THRESHOLD for t in ttls):
                    low_ttl_ips_count += 1
            # If multiple IPs and at least two have low TTLs, consider it flux
            if low_ttl_ips_count >= 2:
                flux_domains.add(domain)
                for ipv4_addr in ip_data.keys():
                    flux_ipv4_addresses.add(ipv4_addr)
                print(f"  Identified flux domain: {domain} with IPs: {list(ip_data.keys())}")
        else:
            # Check for single IP with very low TTL for completeness, though multi-IP is core to flux
            for ipv4_addr, ttls in ip_data.items():
                if any(t <= FLUX_TTL_THRESHOLD / 2 for t in ttls):  # Even lower for single IP
                    # print(f"  Identified potential single-IP flux domain: {domain} ({ipv4_addr})")
                    pass  # Not adding to flux_ipv4_addresses directly if only 1 IP by default

    if not flux_ipv4_addresses:
        print("No fast flux IPv4 addresses identified based on the defined heuristic.")
        print("Exiting without conversion.")
        return

    # --- Step 2: Generate IPv6 Mappings for Identified Flux IPs ---
    print("\nStep 2: Generating IPv6 mappings for identified flux IPs...")
    ipv4_to_ipv6_map = {}
    # Using 2001:db8::/32 which is for documentation/examples
    # We'll assign sequential IPs within a /64 subnet
    base_ipv6_network = ipaddress.IPv6Network('2001:db8:0:1::/64')
    ipv6_generator = base_ipv6_network.hosts()  # Iterator for unique IPv6 addresses

    for ipv4_addr in sorted(list(flux_ipv4_addresses)):  # Sort for consistent mapping
        try:
            # Get the next available IPv6 address
            new_ipv6 = next(ipv6_generator)
            ipv4_to_ipv6_map[ipv4_addr] = str(new_ipv6)
            print(f"  Mapping {ipv4_addr} -> {str(new_ipv6)}")
        except StopIteration:
            print("Warning: Ran out of IPv6 addresses in the assigned range. Some IPs might not be mapped.")
            break

    # --- Step 3: Convert Packets ---
    print("\nStep 3: Converting relevant packets to IPv6...")
    modified_packets = []

    for i, pkt in enumerate(packets):
        modified_pkt = pkt  # Start with the original packet

        # 3.1: Handle DNS Responses (Change A records to AAAA)
        if modified_pkt.haslayer(DNS) and modified_pkt[DNS].qr == 1:  # DNS Response
            current_domain = modified_pkt[DNS].qd.qname.decode('utf-8').strip('.') if modified_pkt[DNS].qd else None

            # Only modify DNS responses for identified flux domains
            if current_domain in flux_domains:
                new_ans = []
                for ans_rr in modified_pkt[DNS].an:
                    if ans_rr.type == 1 and ans_rr.rdata in ipv4_to_ipv6_map:  # A record for a mapped flux IP
                        new_ipv6_addr = ipv4_to_ipv6_map[ans_rr.rdata]
                        # Create AAAA record
                        new_ans_rr = DNSRR(rrname=ans_rr.rrname, type='AAAA', rclass='IN',
                                           ttl=ans_rr.ttl, rdata=new_ipv6_addr)
                        new_ans.append(new_ans_rr)
                    else:
                        new_ans.append(ans_rr)  # Keep other record types as is
                # Replace the answer section
                modified_pkt[DNS].an = new_ans
                # Update QDcount and ANcount if needed, though Scapy often handles this.
                # modified_pkt[DNS].ancount = len(new_ans) # Scapy usually re-calculates

        # 3.2: Convert IP Layer (IPv4 to IPv6) for relevant packets
        # This part handles data traffic to/from the fluxing IPs
        if modified_pkt.haslayer(IP):
            src_ipv4 = modified_pkt[IP].src
            dst_ipv4 = modified_pkt[IP].dst

            if src_ipv4 in ipv4_to_ipv6_map or dst_ipv4 in ipv4_to_ipv6_map:
                try:
                    # Map source and destination IPs
                    new_src_ipv6 = ipv4_to_ipv6_map.get(src_ipv4, str(ipaddress.IPv6Address('::ffff:' + src_ipv4)))
                    new_dst_ipv6 = ipv4_to_ipv6_map.get(dst_ipv4, str(ipaddress.IPv6Address('::ffff:' + dst_ipv4)))

                    # Preserve higher layers
                    next_layer = modified_pkt[IP].payload  # Get the TCP/UDP/ICMP layer

                    # Create new IPv6 packet
                    ipv6_pkt = Ether(src=modified_pkt[Ether].src, dst=modified_pkt[Ether].dst, type=0x86DD) / \
                               IPv6(src=new_src_ipv6, dst=new_dst_ipv6) / \
                               next_layer

                    modified_packets.append(ipv6_pkt)
                    # print(f"  Converted packet {i}: {src_ipv4} -> {new_src_ipv6}, {dst_ipv4} -> {new_dst_ipv6}")
                except Exception as e:
                    print(f"  Warning: Error converting packet {i} (IP layer): {e}. Keeping original.")
                    modified_packets.append(modified_pkt)  # Keep original if conversion fails
            else:
                # If neither src nor dst is a flux IP, keep the original IPv4 packet
                modified_packets.append(modified_pkt)
        else:
            # If not an IP packet, keep as is (e.g., ARP, raw Ethernet)
            modified_packets.append(modified_pkt)

    # --- Step 4: Save the Converted PCAP ---
    print(f"\nStep 4: Saving converted PCAP to: {output_pcap_path}")
    try:
        wrpcap(output_pcap_path, modified_packets)
        print("Conversion complete!")
    except Exception as e:
        print(f"Error saving PCAP: {e}")


# --- How to use the automated function ---
if __name__ == "__main__":
    # YOU ONLY NEED TO CHANGE THESE TWO LINES:
    input_pcap = 'C://Users//RohithRonanki//Documents//ConnectionToFFAgentDetected.pcap'  # Replace with your input PCAP file path
    output_pcap = 'C://Users//RohithRonanki//Desktop//packetlog.pcap'  # Replace with your desired output PCAP file path

    # Example: Create a dummy PCAP for testing if you don't have one
    # from scapy.all import IP, TCP, DNS, DNSQR, DNSRR, Ether
    # from scapy.layers.inet6 import IPv6
    #
    # # Dummy DNS response simulating fast flux (low TTL A records)
    # flux_domain = "malware.example.com."
    # pkts = [
    #     Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(id=123, qr=0, qd=DNSQR(qname=flux_domain)),
    #     Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=12345)/DNS(id=123, qr=1, anCount=2,
    #         an=(DNSRR(rrname=flux_domain, type='A', ttl=60, rdata="1.1.1.1"),
    #             DNSRR(rrname=flux_domain, type='A', ttl=60, rdata="2.2.2.2")))
    # ]
    # # Dummy HTTP request to one of the flux IPs
    # pkts.append(Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/TCP(dport=80, sport=50000, flags="S"))
    # pkts.append(Ether()/IP(src="1.1.1.1", dst="192.168.1.100")/TCP(dport=50000, sport=80, flags="SA"))
    # pkts.append(Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/TCP(dport=80, sport=50000, flags="A")/Raw(load="GET / HTTP/1.1\r\nHost: malware.example.com\r\n\r\n"))
    # pkts.append(Ether()/IP(src="1.1.1.1", dst="192.168.1.100")/TCP(dport=50000, sport=80, flags="A")/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nHello Flux"))
    #
    # wrpcap(input_pcap, pkts)
    # print(f"Dummy PCAP '{input_pcap}' created for testing.")

    automate_ipv4_to_ipv6_fast_flux_conversion(input_pcap, output_pcap)