# server.py
# --------------------------------------------------------------------
# PURE RELAY CHAT SERVER with reliable resend protocol.
# - NEVER corrupts __CRC_ERROR__ replies
# - Client always receives resend request correctly
# - Client always resends correctly
# - Server broadcasts clean messages only
# - Join/leave announcements sent to ALL clients including newcomer
# --------------------------------------------------------------------

import socket
import threading
import struct
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext
from crc import make_packet, verify_and_extract, maybe_corrupt, ERROR_TOKEN

HOST = "0.0.0.0"
PORT = 1234


def recv_all(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf


class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Server Monitor")

        frame = ttk.Frame(root, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(frame)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(left, text="Server Log").pack(anchor=tk.W)
        self.log = scrolledtext.ScrolledText(left, state="disabled", height=20)
        self.log.pack(fill=tk.BOTH, expand=True)

        right = ttk.Frame(frame)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(right, text="Connected Clients").pack(anchor=tk.W)
        self.clients_list = tk.Listbox(right, height=12)
        self.clients_list.pack(fill=tk.X)

        self.clients = {}
        self.clients_lock = threading.Lock()
        self.queue = queue.Queue()

        self.root.after(100, self.process_queue)

    def log_msg(self, t):
        self.log.config(state="normal")
        self.log.insert(tk.END, t + "\n")
        self.log.yview(tk.END)
        self.log.config(state="disabled")

    def process_queue(self):
        while not self.queue.empty():
            event, data = self.queue.get()

            if event == "log":
                self.log_msg(data)

            elif event == "add_client":
                sock, name = data
                with self.clients_lock:
                    self.clients[sock] = name
                self.clients_list.insert(tk.END, name)
                self.log_msg(f"{name} connected.")

            elif event == "remove_client":
                sock = data
                with self.clients_lock:
                    name = self.clients.pop(sock, None)
                if name:
                    try:
                        i = self.clients_list.get(0, tk.END).index(name)
                        self.clients_list.delete(i)
                    except:
                        pass
                    self.log_msg(f"{name} disconnected.")

            elif event == "broadcast":
                self.broadcast(data)

        self.root.after(100, self.process_queue)

    def broadcast(self, text):
        packet = make_packet(text)
        with self.clients_lock:
            items = list(self.clients.items())
        for sock, _ in items:
            try:
                sock.sendall(struct.pack("!I", len(packet)) + packet)
            except:
                pass


# =====================================================================

def client_thread(sock, addr, gui: ServerGUI):
    try:
        # Receive name
        header = recv_all(sock, 4)
        if not header:
            return
        (length,) = struct.unpack("!I", header)
        packet = recv_all(sock, length)
        valid, name = verify_and_extract(packet)

        if not valid:
            name = "Unknown"

        gui.queue.put(("add_client", (sock, name)))
        gui.queue.put(("broadcast", f"{name} has entered the chat. Welcome!"))

        last_request_resend = False

        while True:
            header = recv_all(sock, 4)
            if not header:
                break

            (length,) = struct.unpack("!I", header)
            packet = recv_all(sock, length)
            if not packet:
                break

            valid, text = verify_and_extract(packet)

            # Bad message → request resend
            if not valid:
                gui.queue.put(("log", f"Corrupted message from {name}, requesting resend."))

                error_packet = make_packet(ERROR_TOKEN)   # NEVER corrupted
                try:
                    sock.sendall(struct.pack("!I", len(error_packet)) + error_packet)
                except:
                    pass

                last_request_resend = True
                continue

            # Ignore ERROR_TOKEN echoes
            if text == ERROR_TOKEN:
                continue

            # Clean message received
            if last_request_resend:
                gui.queue.put(("log", f"{name} resent successfully."))
                last_request_resend = False

            gui.queue.put(("broadcast", f"{name} → {text}"))

    finally:
        try:
            sock.close()
        except:
            pass

        gui.queue.put(("remove_client", sock))

        with gui.clients_lock:
            name = gui.clients.get(sock, "Unknown")

        gui.queue.put(("broadcast", f"{name} has left the chat."))


# =====================================================================

def accept_loop(server_sock, gui):
    while True:
        c, addr = server_sock.accept()
        threading.Thread(target=client_thread, args=(c, addr, gui), daemon=True).start()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    root = tk.Tk()
    gui = ServerGUI(root)
    gui.log_msg(f"Server running on {HOST}:{PORT}")

    threading.Thread(target=accept_loop, args=(srv, gui), daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    main()
