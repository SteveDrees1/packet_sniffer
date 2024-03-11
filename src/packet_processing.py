import os
from datetime import datetime, timedelta
from threading import Thread

from colorama import init
from scapy.all import IP, TCP, UDP, ICMP, sniff
from scapy.utils import PcapWriter

# Initialize Colorama
init()

# Settings and global variables
LOG_DIR = "packet_logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

# Batch and capture settings
BATCH_DURATION = 60  # Time in seconds to aggregate packets
BATCH_SIZE = 100
MAX_CAPTURE_DURATION = 60  # 60 seconds = 1 minute

# Initialize batch and capture variables
packet_batch = []  # This is the global packet batch
batch_start_time = datetime.now()
capture_start_time = datetime.now()

# Control flag
sniffing = False


def get_packet_color(packet):
    """Returns color codes based on the packet type."""
    if TCP in packet:
        return "red"  # Red for TCP packets
    elif UDP in packet:
        return "blue"  # Blue for UDP packets
    elif ICMP in packet:
        return "green"  # Green for ICMP packets
    elif IP in packet:
        return "yellow"  # Yellow for IP packets
    else:
        return "black"  # Default color for other packets


def process_packet(packet, packet_queue):
    """Processes packets and enqueues them into the packet queue."""

    global packet_batch, batch_start_time

    packet_color = get_packet_color(packet)  # Get color for the packet
    packet_summary = packet.summary()  # Get packet summary
    packet_info = {"text": packet_summary, "color": packet_color}  # Create packet info dictionary
    packet_queue.put(packet_info)  # Put packet info into the queue

    # Check if the maximum capture duration has been reached
    if datetime.now() - capture_start_time > timedelta(seconds=MAX_CAPTURE_DURATION):
        log_packet_batch()  # Log any remaining packets before stopping
        print("Maximum capture duration reached. Stopping...")
        return "STOP"  # Return a signal to stop the sniffing loop

    packet_batch.append(packet)

    # Log the batch based on time or size criteria
    current_time = datetime.now()
    if (current_time - batch_start_time).seconds >= BATCH_DURATION or len(packet_batch) >= BATCH_SIZE:
        log_packet_batch()
        packet_batch = []  # Reset batch
        batch_start_time = current_time


def log_packet_batch():
    """Logs packets from the batch to a PCAP file."""
    global packet_batch
    if not packet_batch:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(LOG_DIR, f"packet_batch_{timestamp}.pcap")
    iterator = 1
    while os.path.exists(filename):
        filename = os.path.join(LOG_DIR, f"packet_batch_{timestamp}_PART{iterator}.pcap")
        iterator += 1

    with PcapWriter(filename, append=True, sync=True) as pcap_writer:
        for packet in packet_batch:
            pcap_writer.write(packet)
    print(f"Logged {len(packet_batch)} packets to {filename}")
    packet_batch.clear()


def start_sniffing(packet_queue):
    """Starts packet sniffing in a separate thread."""
    global sniffing
    if not sniffing:
        sniffing = True
        Thread(target=lambda: sniff(prn=lambda pkt: process_packet(pkt, packet_queue), store=False,
                                    stop_filter=lambda x: not sniffing)).start()


def stop_sniffing():
    """Stops packet sniffing."""
    global sniffing
    sniffing = False
