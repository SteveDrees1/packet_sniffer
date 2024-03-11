from scapy.all import PcapWriter
import os
from datetime import datetime, timedelta

from scapy.sendrecv import sniff

# Directory to store PCAP files
LOG_DIR = "packet_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Batch and capture settings
BATCH_DURATION = 60  # Time in seconds to aggregate packets
BATCH_SIZE = 100  # Max number of packets per batch
MAX_CAPTURE_DURATION = 300  # Maximum capture duration in seconds (e.g., 5 minutes)

# Initialize batch and capture variables
packet_batch = []
batch_start_time = datetime.now()
capture_start_time = datetime.now()


def log_packet_batch(packet_batch):
    """
    Logs a batch of packets to a PCAP file, named with the current timestamp.
    """
    if not packet_batch:  # Don't log if the batch is empty
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(LOG_DIR, f"packet_batch_{timestamp}.pcap")
    with PcapWriter(filename, append=True, sync=True) as pcap_writer:
        for packet in packet_batch:
            pcap_writer.write(packet)
    print(f"Logged {len(packet_batch)} packets to {filename}")


def process_packet(packet):
    """
    Adds packets to a batch and logs the batch based on time or size criteria.
    Also checks for the maximum capture duration to stop capturing.
    """
    global packet_batch, batch_start_time

    # Check if the maximum capture duration has been reached
    if datetime.now() - capture_start_time > timedelta(seconds=MAX_CAPTURE_DURATION):
        log_packet_batch(packet_batch)  # Log any remaining packets before stopping
        print("Maximum capture duration reached. Stopping...")
        return "STOP"  # Return a signal to stop the sniffing loop

    packet_batch.append(packet)

    # Log the batch based on time or size criteria
    current_time = datetime.now()
    if (current_time - batch_start_time).seconds >= BATCH_DURATION or len(packet_batch) >= BATCH_SIZE:
        log_packet_batch(packet_batch)
        packet_batch = []  # Reset batch
        batch_start_time = current_time


def start_sniffing():
    """
    Starts the packet sniffing process and automatically stops after a set duration.
    """
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=False, stop_filter=lambda x: process_packet(x) == "STOP")


if __name__ == "__main__":
    start_sniffing()
