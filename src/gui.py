import queue
import tkinter as tk
from tkinter import scrolledtext

class PacketSnifferApp(tk.Tk):
    def __init__(self, start_sniffing_callback, stop_sniffing_callback, packet_queue):
        super().__init__()
        self.start_sniffing_callback = start_sniffing_callback
        self.stop_sniffing_callback = stop_sniffing_callback
        self.packet_queue = packet_queue  # Queue to hold packets for display

        self.title("Packet Sniffer")
        self.geometry("800x600")

        self.start_button = tk.Button(self, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=20)

        self.stop_button = tk.Button(self, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=20)

        # Create a ScrolledText widget for displaying packet information
        self.packet_display = scrolledtext.ScrolledText(self, width=100, height=20)
        self.packet_display.pack(pady=10)

        self.update_packet_display()  # Start the update loop for displaying packets

    def start_sniffing(self):
        self.start_sniffing_callback()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        self.stop_sniffing_callback()
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)

    def update_packet_display(self):
        # Check if there are packets to display
        try:
            while not self.packet_queue.empty():
                packet_info = self.packet_queue.get_nowait()  # Get a packet info from the queue

                # Insert packet text into the Text widget
                start_index = self.packet_display.index(tk.END)
                self.packet_display.insert(tk.END, packet_info["text"] + '\n')
                end_index = self.packet_display.index(tk.END)

                # Apply color tag to the inserted text
                self.packet_display.tag_add("color_tag", start_index, end_index)
                self.packet_display.tag_config("color_tag", foreground=packet_info["color"])

                # Auto-scroll to the end
                self.packet_display.yview(tk.END)
        except queue.Empty:
            pass

        # Schedule the next update
        self.after(100, self.update_packet_display)
