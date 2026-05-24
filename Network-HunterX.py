import pyshark
from tabulate import tabulate

PCAP_FILE = "Pfile.pcapng"


def parse_packets(pcap_file):

    capture = pyshark.FileCapture(pcap_file, keep_packets=True)
    packet_db = {}
    table = []

    seq = 1
    for pkt in capture:
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_mac = pkt.eth.src
            dst_mac = pkt.eth.dst

            protocol = "OTHER"
            src_port = "-"
            dst_port = "-"

            if "TCP" in pkt:
                protocol = "TCP"
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            elif "UDP" in pkt:
                protocol = "UDP"
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport

            table.append([
                seq,
                src_ip,
                src_port,
                src_mac,
                dst_ip,
                dst_port,
                dst_mac,
                protocol
            ])

            packet_db[seq] = pkt
            seq += 1

        except AttributeError:
            
            continue

    return table, packet_db


def print_table(table):
    headers = [
        "SEQ #",
        "Source IP",
        "Source Port",
        "Source MAC",
        "Destination IP",
        "Destination Port",
        "Destination MAC",
        "TCP / UDP"
    ]

    print("\n=== Packet Summary Table ===\n")
    print(tabulate(table, headers=headers, tablefmt="grid"))


def inspect_packet(packet_db):
    try:
        seq = int(input("\nEnter packet SEQ # to inspect: "))

        if seq in packet_db:
            print("\n=== Full Packet Details ===\n")
            print(packet_db[seq])
        else:
            print("[-] Invalid packet sequence number.")

    except ValueError:
        print("[-] Please enter a valid number.")


def main():
    table, packet_db = parse_packets(PCAP_FILE)
    print_table(table)
    inspect_packet(packet_db)


if __name__ == "__main__":
    main()
