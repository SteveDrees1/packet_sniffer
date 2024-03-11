from scapy.all import sniff
from packet_processing import process_packet


def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_sniffing()
