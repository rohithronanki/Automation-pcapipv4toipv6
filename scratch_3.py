from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6
import ipaddress
import random
import os


def generate_random_unique_ipv6(used_ips_set, base_prefix_str="2001:db8::/32"):
    """
    Generates a random unique IPv6 address within a specified prefix.
    It ensures the generated address has not been used before in this session.
    """

    # Ensure the base prefix is a valid IPv6 network object
    try:
        base_network = ipaddress.IPv6Network(base_prefix_str)
    except ipaddress.AddressValueError:
        print(f"Error: Invalid IPv6 prefix provided: {base_prefix_str}. Using default 2001:db8::/32.")
        base_network = ipaddress.IPv6Network("2001:db8::/32")

    # The number of bits available for the host portion of the address
    host_bits = 128 - base_network.prefixlen

    # To prevent very small ranges from breaking, ensure there's enough space
    if host_bits <= 0:
        raise ValueError(f"IPv6 prefix {base_prefix_str} is too narrow to generate random hosts.")

    while True:
        # Generate a random integer for the host part
        random_host_int = random.getrandbits(host_bits)

        # Combine the network address with the random host part
        generated_ipv6_int = int(base_network.network_address) | random_host_int

        # Convert to IPv6Address object
        new_ipv6_address_obj = ipaddress.IPv6Address(generated_ipv6_int)

        # Ensure the generated address is within the specified network (important for subnets like /64)
        if new_ipv6_address_obj in base_network and str(new_ipv6_address_obj) not in used_ips_set:
            return str(new_ipv6_address_obj)


def convert_ipv4_pcap_to_random_ipv6(input_pcap_path, output_pcap_path, ipv6_prefix="2001:db8::/32"):
    """
    Reads an IPv4 PCAP, converts IPv4 addresses in the IP header to random IPv6 addresses,
    and saves the modified PCAP as IPv6.

    Args:
        input_pcap_path (str): Path to the input IPv4 PCAP file.
        output_pcap_path (str): Path to save the converted IPv6 PCAP file.
        ipv6_prefix (str): The IPv6 prefix (e.g., "2001:db8::/32") to use for generating random addresses.
                           Using a /32 or /48 is usually good to ensure enough random space.
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

    ipv4_to_ipv6_map = {}  # Stores the mapping from IPv4 string to generated IPv6 string
    used_ipv6_addresses_set = set()  # Stores all generated IPv6 addresses to ensure uniqueness
    modified_packets = []

    print("Converting IPv4 packets to IPv6 with random addresses...")
    for i, pkt in enumerate(packets):
        # Only process packets that have an IPv4 layer
        if pkt.haslayer(IP):
            ipv4_src = pkt[IP].src
            ipv4_dst = pkt[IP].dst

            # --- Map Source IPv4 to IPv6 ---
            if ipv4_src not in ipv4_to_ipv6_map:
                try:
                    new_ipv6 = generate_random_unique_ipv6(used_ipv6_addresses_set, ipv6_prefix)
                    ipv4_to_ipv6_map[ipv4_src] = new_ipv6
                    used_ipv6_addresses_set.add(new_ipv6)
                    print(f"  Mapped {ipv4_src} -> {new_ipv6}")
                except ValueError as ve:
                    print(f"  Error generating IPv6 for {ipv4_src}: {ve}. Skipping conversion for this IP.")
                    modified_packets.append(pkt)  # Keep original if IP cannot be mapped
                    continue  # Skip to next packet
            ipv6_src = ipv4_to_ipv6_map[ipv4_src]

            # --- Map Destination IPv4 to IPv6 ---
            if ipv4_dst not in ipv4_to_ipv6_map:
                try:
                    new_ipv6 = generate_random_unique_ipv6(used_ipv6_addresses_set, ipv6_prefix)
                    ipv4_to_ipv6_map[ipv4_dst] = new_ipv6
                    used_ipv6_addresses_set.add(new_ipv6)
                    print(f"  Mapped {ipv4_dst} -> {new_ipv6}")
                except ValueError as ve:
                    print(f"  Error generating IPv6 for {ipv4_dst}: {ve}. Skipping conversion for this IP.")
                    modified_packets.append(pkt)  # Keep original if IP cannot be mapped
                    continue  # Skip to next packet
            ipv6_dst = ipv4_to_ipv6_map[ipv4_dst]

            # --- Create new IPv6 packet ---
            try:
                # Create a new Ethernet layer for IPv6 (type=0x86DD)
                # Copy original MAC addresses if available, otherwise Scapy uses defaults.
                ether_src = pkt[Ether].src if pkt.haslayer(Ether) else None
                ether_dst = pkt[Ether].dst if pkt.haslayer(Ether) else None

                # Remove the old IPv4 layer and insert a new IPv6 layer
                # Scapy's / operator automatically handles higher layers and checksums
                if pkt.haslayer(Ether):
                    new_pkt = Ether(src=ether_src, dst=ether_dst, type=0x86DD) / \
                              IPv6(src=ipv6_src, dst=ipv6_dst) / \
                              pkt[IP].payload  # Copy the higher-layer payload (TCP, UDP, ICMP etc.)
                else:  # Handle cases where there is no Ethernet layer (e.g., raw IP captures)
                    new_pkt = IPv6(src=ipv6_src, dst=ipv6_dst) / \
                              pkt[IP].payload  # Copy the higher-layer payload

                modified_packets.append(new_pkt)

            except Exception as e:
                print(
                    f"  Warning: Could not convert IPv4 packet {i} (from {ipv4_src} to {ipv4_dst}). Error: {e}. Keeping original IPv4 packet.")
                modified_packets.append(pkt)  # Append original IPv4 packet if conversion to IPv6 fails
        else:
            # If it's already an IPv6 packet, or another protocol (e.g., ARP), keep it as is
            modified_packets.append(pkt)

    print(f"\nSaving converted PCAP to: {output_pcap_path}")
    try:
        wrpcap(output_pcap_path, modified_packets)
        print("Conversion complete!")
        print(f"Total packets processed: {len(packets)}")
        print(f"Total IPv4 packets converted to IPv6: {len([p for p in modified_packets if p.haslayer(IPv6)])}")
        print(f"Total unique IPv4s mapped to IPv6: {len(ipv4_to_ipv6_map)}")
    except Exception as e:
        print(f"Error saving converted PCAP: {e}")


if __name__ == "__main__":
    # --- USER INPUT: Customize these paths and prefix ---
    input_pcap_file = 'C:\\Users\\RohithRonanki\\Desktop\\TC2_v4.pcap'  # <--- Set your input PCAP path
    output_pcap_file = 'C:\\Users\\RohithRonanki\\Desktop\\converted_random_ipv6.pcap'  # <--- Set your desired output PCAP path

    # Define the IPv6 prefix to use for generating random addresses.
    # "2001:db8::/32" is reserved for documentation and examples and provides a very large space.
    # You can also use "fd00::/8" for Unique Local Addresses (ULA) which are private.
    target_ipv6_prefix_for_generation = "2001:db8::/32"

    # --- Run the conversion ---
    convert_ipv4_pcap_to_random_ipv6(input_pcap_file, output_pcap_file, target_ipv6_prefix_for_generation)

    print("\n--- IMPORTANT LIMITATION ---")
    print("This script converts IP headers (IPv4 to IPv6) and recomputes checksums.")
    print("However, it DOES NOT modify IPv4 addresses that might be embedded within the ")
    print("APPLICATION LAYER PAYLOAD (e.g., HTTP body, FTP commands, DNS query/response data, custom protocols).")
    print("If your detection relies on these embedded IPs, this script will not be sufficient.")