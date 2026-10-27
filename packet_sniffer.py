import socket
import struct
import textwrap
from scapy.all import sniff, conf

conf.use_pcap = True

TAB_1='\t - '
TAB_2='\t\t - '
TAB_3='\t\t\t - '
TAB_4='\t\t\t\t - '

DATA_TAB_1='\t '
DATA_TAB_2='\t\t '
DATA_TAB_3='\t\t\t '
DATA_TAB_4='\t\t\t\t '


def main():
    print("Packet Sniffer started.")
    print("Listening for packets... Press Ctrl+C to stop.")

    conf.use_pcap = True

    try:
        print("Using interface:", conf.iface)
        print("Using listener:", conf.L2listen)

        sniff(
            iface=conf.iface,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket Sniffer stopped.")

    except Exception as error:
        print(f"Capture error: {error}")



def process_packet(packet):
    raw_data = bytes(packet)

    try:
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print("\nEthernet Frame:")
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(
            dest_mac, src_mac, eth_proto
        ))

        if eth_proto != 8 or len(data) < 20:
            return

        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

        if len(data) < 0 or header_length < 20:
            return

        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(
            version, header_length, ttl
        ))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(
            proto, src, target
        ))

        if proto == 1 and len(data) >= 4:
            icmp_type, code, checksum, data = icmp_packet(data)
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(
                icmp_type, code, checksum
            ))

        elif proto == 6 and len(data) >= 20:
            (src_port, dest_port, sequence, acknowledgement,
             flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
             flag_fin, data) = tcp_segment(data)

            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(
                src_port, dest_port
            ))
            print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(
                sequence, acknowledgement
            ))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
            ))

        elif proto == 17 and len(data) >= 8:
            src_port, dest_port, length, data = udp_segment(data)
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                src_port, dest_port, length
            ))

    except (struct.error, IndexError, ValueError) as error:
        print(f"Skipping invalid or incomplete packet: {error}")



# Unpack ethernet frame 
def ethernet_frame(data):
    dest_mac, src_mac, proto=struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] 

#  return properly formatted MAC address (like AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, IPv4(src), IPv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def IPv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_segment(data):
    if len(data) < 8:
        raise ValueError("Incomplete UDP header")

    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()