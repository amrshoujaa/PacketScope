
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from queue import Queue, Empty
from datetime import datetime
import threading

from scapy.all import (
    AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP, wrpcap, conf
)
conf.use_pcap = True

class PacketScope:
    MAX_PACKETS = 5000
    MAX_ROWS = 500

    def __init__(self, root):
        self.root = root
        self.root.title("PacketScope | Network Analyzer")
        self.root.geometry("1150x720")
        self.root.minsize(850, 500)
        self.root.configure(bg="#F4F8FC")

        self.sniffer = None
        self.packet_queue = Queue()
        self.packets = []
        self.visible_packets = []
        self.protocol_counts = {}
        self.total_bytes = 0
        self.dropped_from_memory = 0
        self.closing = False

        self.build_ui()
        self.root.after(100, self.process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def build_ui(self):
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        # Bright, clean light theme
        style.configure("TFrame", background="#F4F8FC")
        style.configure(
            "TLabel",
            background="#F4F8FC",
            foreground="#243447",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Title.TLabel",
            background="#F4F8FC",
            foreground="#123047",
            font=("Segoe UI", 20, "bold"),
        )
        style.configure(
            "TButton",
            background="#DCEAF5",
            foreground="#183B56",
            font=("Segoe UI", 10),
            padding=(10, 6),
        )
        style.map("TButton", background=[("active", "#C5E4F6")])
        style.configure(
            "TEntry",
            fieldbackground="#FFFFFF",
            foreground="#243447",
            padding=5,
        )
        style.configure(
            "Treeview",
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground="#243447",
            rowheight=29,
            font=("Segoe UI", 10),
            bordercolor="#D7E3EE",
            lightcolor="#D7E3EE",
            darkcolor="#D7E3EE",
        )
        style.configure(
            "Treeview.Heading",
            background="#DCEAF5",
            foreground="#183B56",
            font=("Segoe UI", 10, "bold"),
            padding=7,
        )
        style.map(
            "Treeview",
            background=[("selected", "#B9E7F5")],
            foreground=[("selected", "#123047")],
        )

        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main, text="PacketScope", style="Title.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            main, text="Network Traffic Analyzer"
        ).pack(anchor="w", pady=(0, 12))

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=(0, 10))

        ttk.Label(controls, text="Capture filter:").pack(side="left")

        self.capture_filter = tk.StringVar()
        ttk.Entry(
            controls, textvariable=self.capture_filter, width=28
        ).pack(side="left", padx=6)

        self.start_btn = ttk.Button(
            controls, text="Start Capture", command=self.start_capture
        )
        self.start_btn.pack(side="left", padx=3)

        self.stop_btn = ttk.Button(
            controls, text="Stop Capture", command=self.stop_capture,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=3)

        ttk.Button(
            controls, text="Export PCAP", command=self.export_pcap
        ).pack(side="left", padx=3)

        stats = ttk.Frame(main)
        stats.pack(fill="x", pady=(0, 10))

        self.packet_stat = tk.StringVar(value="Packets: 0")
        self.byte_stat = tk.StringVar(value="Captured bytes: 0")
        self.protocol_stat = tk.StringVar(value="Protocols: —")

        for variable in (
            self.packet_stat, self.byte_stat, self.protocol_stat
        ):
            ttk.Label(stats, textvariable=variable).pack(
                side="left", padx=(0, 18)
            )

        search_row = ttk.Frame(main)
        search_row.pack(fill="x", pady=(0, 6))

        ttk.Label(search_row, text="Display filter:").pack(side="left")

        self.search = tk.StringVar()
        self.search.trace_add("write", self.refresh_table)

        ttk.Entry(
            search_row, textvariable=self.search
        ).pack(side="left", fill="x", expand=True, padx=6)

        table_frame = ttk.Frame(main)
        table_frame.pack(fill="both", expand=True)

        columns = (
            "time", "source", "destination",
            "protocol", "src_port", "dst_port", "length"
        )

        self.table = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse"
        )

        # Each protocol gets its own readable, pastel row color.
        self.table.tag_configure("TCP", background="#D7F5E8", foreground="#236B4B")
        self.table.tag_configure("UDP", background="#DCEBFF", foreground="#2457A6")
        self.table.tag_configure("ICMP", background="#FFE8C7", foreground="#8A4B08")
        self.table.tag_configure("ARP", background="#EDE0FF", foreground="#6336A3")
        self.table.tag_configure("IPv6", background="#D9F4F7", foreground="#176873")
        self.table.tag_configure("IPv4", background="#E5EAFE", foreground="#374A8A")
        self.table.tag_configure("Other", background="#EDF0F4", foreground="#4B5563")

        headings = {
            "time": "Time",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "src_port": "Source Port",
            "dst_port": "Destination Port",
            "length": "Length"
        }

        widths = {
            "time": 85, "source": 170, "destination": 170,
            "protocol": 90, "src_port": 90, "dst_port": 90,
            "length": 80
        }

        for column in columns:
            self.table.heading(column, text=headings[column])
            self.table.column(
                column, width=widths[column], minwidth=60
            )

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.table.yview
        )
        self.table.configure(yscrollcommand=scrollbar.set)

        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.table.bind("<<TreeviewSelect>>", self.show_details)

        ttk.Label(
            main, text="Selected Packet Details"
        ).pack(anchor="w", pady=(10, 3))

        self.details = tk.Text(
            main,
            height=6,
            wrap="word",
            state="disabled",
            bg="#FFFFFF",
            fg="#243447",
            insertbackground="#243447",
            selectbackground="#B9E7F5",
            relief="solid",
            borderwidth=1,
            font=("Consolas", 10),
            padx=8,
            pady=6,
        )
        self.details.pack(fill="x")

        self.status = tk.StringVar(value="Ready")
        ttk.Label(
            main, textvariable=self.status, relief="sunken", anchor="w"
        ).pack(fill="x", pady=(8, 0))

    @staticmethod
    def describe_packet(packet):
        src = dst = "-"
        src_port = dst_port = "-"
        protocol = "Other"

        if ARP in packet:
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            protocol = "ARP"

        elif IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "IPv4"

        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            protocol = "IPv6"

        if TCP in packet:
            protocol = "TCP"
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)

        elif UDP in packet:
            protocol = "UDP"
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)

        elif ICMP in packet:
            protocol = "ICMP"

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%H:%M:%S")

        return (
            timestamp, src, dst, protocol,
            src_port, dst_port, str(len(packet))
        )

    def start_capture(self):
        if self.sniffer is not None:
            return

        capture_filter = self.capture_filter.get().strip() or None

        try:
            sniffer = AsyncSniffer(
                iface=conf.iface,
                filter=capture_filter,
                prn=self.packet_queue.put,
                store=False
            )
            sniffer.start()
            self.sniffer = sniffer

            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status.set(f"Capturing on {conf.iface}")

        except Exception as error:
            self.sniffer = None
            messagebox.showerror(
                "Capture Error",
                f"Could not start packet capture:\n{error}"
            )

    def stop_capture(self):
        sniffer = self.sniffer
        if sniffer is None:
            return

        self.sniffer = None
        self.stop_btn.config(state="disabled")
        self.status.set("Stopping capture...")

        def stop_worker():
            error = None
            try:
                if sniffer.running:
                    sniffer.stop()
            except Exception as exc:
                error = str(exc)

            self.packet_queue.put(("__STOPPED__", error))

        threading.Thread(target=stop_worker, daemon=True).start()

    def process_queue(self):
        if self.closing:
            return

        changed = False

        # Limit work per tick to keep the GUI responsive.
        for _ in range(300):
            try:
                item = self.packet_queue.get_nowait()
            except Empty:
                break

            if isinstance(item, tuple) and item[0] == "__STOPPED__":
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
                self.status.set(
                    f"Capture stopped: {item[1]}"
                    if item[1] else "Capture stopped"
                )
                continue

            packet = item
            self.packets.append(packet)
            self.total_bytes += len(packet)

            row = self.describe_packet(packet)
            protocol = row[3]
            self.protocol_counts[protocol] = (
                self.protocol_counts.get(protocol, 0) + 1
            )

            if len(self.packets) > self.MAX_PACKETS:
                removed = self.packets.pop(0)
                self.dropped_from_memory += 1
                # Byte/protocol statistics remain cumulative.

            changed = True

        if changed:
            self.refresh_table()
            self.update_stats()

        self.root.after(100, self.process_queue)

    def refresh_table(self, *_):
        query = self.search.get().strip().lower()

        selected = self.table.selection()
        selected_packet = None
        if selected:
            old_index = int(selected[0])
            if 0 <= old_index < len(self.visible_packets):
                selected_packet = self.visible_packets[old_index]

        candidates = self.packets[-self.MAX_ROWS:]
        
        visible = []

        for packet in reversed(self.packets):
            row = self.describe_packet(packet)

            if query and query not in " ".join(row).lower():
                continue

            visible.append(packet)

    # Display only the latest 500 matching packets
            if len(visible) >= self.MAX_ROWS:
                break


        self.visible_packets = visible

        self.table.delete(*self.table.get_children())

        for index, packet in enumerate(visible):
            row = self.describe_packet(packet)
            protocol = row[3]
            self.table.insert(
                "", "end", iid=str(index),
                values=row,
                tags=(protocol if protocol in {
                    "TCP", "UDP", "ICMP", "ARP", "IPv6", "IPv4"
                } else "Other",),
            )

        if selected_packet in visible:
            self.table.selection_set(str(visible.index(selected_packet)))

    def update_stats(self):
        self.packet_stat.set(
            f"Packets in memory: {len(self.packets)}"
        )
        self.byte_stat.set(f"Captured bytes: {self.total_bytes:,}")

        summary = ", ".join(
            f"{name}: {count}"
            for name, count in sorted(self.protocol_counts.items())
        ) or "—"

        self.protocol_stat.set(f"Protocols: {summary}")

    def show_details(self, _event=None):
        selection = self.table.selection()
        if not selection:
            return

        index = int(selection[0])
        if not 0 <= index < len(self.visible_packets):
            return

        packet = self.visible_packets[index]
        summary = (
            f"Summary: {packet.summary()}\n"
            f"Length: {len(packet)} bytes\n"
            f"Layers: {packet.layers()}\n"
            "Payload contents are not displayed by default."
        )

        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", summary)
        self.details.config(state="disabled")

    def export_pcap(self):
        if not self.packets:
            messagebox.showinfo(
                "Export PCAP", "No packets are available to export."
            )
            return

        path = filedialog.asksaveasfilename(
            title="Export captured packets",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")]
        )

        if not path:
            return

        try:
            wrpcap(path, self.packets)
            messagebox.showinfo(
                "Export PCAP",
                f"Exported {len(self.packets)} packets to:\n{path}\n\n"
                "Only packets currently retained in memory are exported."
            )
        except Exception as error:
            messagebox.showerror("Export Error", str(error))

    def close(self):
        self.closing = True
        sniffer = self.sniffer
        self.sniffer = None

        if sniffer is not None:
            try:
                if sniffer.running:
                    sniffer.stop(join=False)
            except Exception:
                pass

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketScope(root)
    root.mainloop()
