# main.py
import queue
from src.gui import PacketSnifferApp
from src.packet_processing import start_sniffing, stop_sniffing

if __name__ == "__main__":
    packet_queue = queue.Queue()  # Instantiate the packet queue here
    # Modify the lambda to pass packet_queue to start_sniffing correctly
    app = PacketSnifferApp(lambda: start_sniffing(packet_queue), stop_sniffing, packet_queue)

    app.mainloop()
