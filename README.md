import socket
import struct
import binascii

# Define the MAC address formatting
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Unpack Ethernet Frame
def ethernet_frame(data):
    eth_header = struct.unpack("!6s6sH", data[:14])
    dst_mac = get_mac_addr(eth_header[0])
    src_mac = get_mac_addr(eth_header[1])
    proto = eth_header[2]
    return dst_mac, src_mac, proto, data[14:]

# Unpack IPv4 Header
def ipv4_header(data):
    header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version = header[0] >> 4
    ttl = header[5]
    proto = header[6]
    src_ip = socket.inet_ntoa(header[8])
    dst_ip = socket.inet_ntoa(header[9])
    return version, ttl, proto, src_ip, dst_ip, data[20:]

# Unpack ICMP Header
def icmp_header(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

# Print packet details
def print_packet_details(proto, src_ip, dst_ip, data):
    if proto == 1:  # ICMP
        print(f"ICMP Packet from {src_ip} to {dst_ip}")
        icmp_type, code, checksum, _ = icmp_header(data)
        print(f"ICMP Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
    elif proto == 6:  # TCP (simplified)
        print(f"TCP Packet from {src_ip} to {dst_ip}")
        print(f"Data (TCP): {data[:40]}")
    elif proto == 17:  # UDP
        print(f"UDP Packet from {src_ip} to {dst_ip}")
        print(f"Data (UDP): {data[:40]}")
    else:
        print(f"Other Protocol Packet from {src_ip} to {dst_ip}")

# Main packet sniffing function
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))  # Ethernet and IPv4 packets

    while True:
        raw_data, _ = conn.recvfrom(65536)  # Capture packets
        dst_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print(f"Ethernet Frame: Src MAC: {src_mac}, Dst MAC: {dst_mac}")

        if eth_proto == 0x0800:  # IPv4
            version, ttl, proto, src_ip, dst_ip, data = ipv4_header(data)
            print(f"IPv4 Packet: {src_ip} -> {dst_ip}")
            print_packet_details(proto, src_ip, dst_ip, data)

if __name__ == "__main__":
    main()
