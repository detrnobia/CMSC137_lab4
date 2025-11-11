# server.py
import socket
import threading
import struct
import random
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext
from crc import make_packet, verify_and_extract

HOST = '0.0.0.0'
PORT = 1234
ERROR_TOKEN = '__CRC_ERROR__'
SIMULATED_ERROR_RATE = 0.10  # 10% chance to flip a bit on send

# helper: receive exactly n bytes
def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf

# corrupt payload with single-bit flip with a probability
def maybe_corrupt(payload: bytes) -> bytes:
    if random.random() < SIMULATED_ERROR_RATE and len(payload) > 0:
        b_idx = random.randrange(len(payload))
        bit = 1 << random.randrange(8)
        corrupted = bytearray(payload)
        corrupted[b_idx] ^= bit
        return bytes(corrupted)
    return payload

class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Server - Multi-client with CRC (GUI)")
        root.geometry("720x520")

        frm = ttk.Frame(root, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(left, text="Server Log").pack(anchor=tk.W)
        self.log = scrolledtext.ScrolledText(left, state='disabled', height=25)
        self.log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        right = ttk.Frame(frm, width=260)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Label(right, text="Connected Clients").pack(anchor=tk.W)
        self.clients_list = tk.Listbox(right, height=8)
        self.clients_list.pack(fill=tk.X, padx=4, pady=4)

        ttk.Label(right, text="Send to selected client").pack(anchor=tk.W, pady=(8,0))
        self.entry = ttk.Entry(right)
        self.entry.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(right, text="Send", command=self.send_to_client).pack(padx=4, pady=4)

        ttk.Label(right, text="Server status").pack(anchor=tk.W, pady=(12,0))
        self.status = ttk.Label(right, text="Running", foreground="green")
        self.status.pack(anchor=tk.W, padx=4)

        self.message_queue = queue.Queue()
        self.clients_lock = threading.Lock()

        # map socket -> (name, addr)
        self.clients = {}

        self.root.after(100, self.process_queue)

    def process_queue(self):
        while not self.message_queue.empty():
            kind, payload = self.message_queue.get()
            if kind == 'log':
                self._append_log(payload)
            elif kind == 'add_client':
                sock, name = payload
                with self.clients_lock:
                    self.clients[sock] = name
                self.clients_list.insert(tk.END, name)
                self._append_log(f"Client '{name}' connected.")
            elif kind == 'remove_client':
                sock = payload
                with self.clients_lock:
                    name = self.clients.pop(sock, None)
                # remove from listbox
                if name:
                    idxs = self.clients_list.get(0, tk.END)
                    try:
                        i = idxs.index(name)
                        self.clients_list.delete(i)
                    except ValueError:
                        pass
                    self._append_log(f"Client '{name}' disconnected.")
            elif kind == 'received':
                name, text = payload
                self._append_log(f"{name} → {text}")
            elif kind == 'sent':
                name, text = payload
                self._append_log(f"Server → {name}: {text}")
        self.root.after(100, self.process_queue)

    def _append_log(self, text):
        self.log.config(state='normal')
        self.log.insert(tk.END, text + "\n")
        self.log.yview(tk.END)
        self.log.config(state='disabled')

    def send_to_client(self):
        msg = self.entry.get().strip()
        if not msg:
            return
        sel = self.clients_list.curselection()
        if not sel:
            self._append_log("No client selected to send to.")
            return
        name = self.clients_list.get(sel[0])
        # find socket by name
        target_sock = None
        with self.clients_lock:
            for s, n in self.clients.items():
                if n == name:
                    target_sock = s
                    break
        if target_sock:
            try:
                payload = make_packet(f"Server: {msg}")
                payload = maybe_corrupt(payload)
                target_sock.sendall(struct.pack('!I', len(payload)) + payload)
                self.message_queue.put(('sent', (name, msg)))
            except Exception as e:
                self._append_log(f"Failed to send to {name}: {e}")
        self.entry.delete(0, tk.END)

def client_thread(sock, addr, server_gui: ServerGUI):
    try:
        # first, read 4-byte name length and name packet
        # We'll expect the client to immediately send a name packet in same length-prefixed format
        len_bytes = recv_all(sock, 4)
        if not len_bytes:
            sock.close()
            return
        (length,) = struct.unpack('!I', len_bytes)
        payload = recv_all(sock, length)
        if not payload:
            sock.close()
            return

        ok, name = verify_and_extract(payload)
        # even if corrupted, take best-effort name
        server_gui.message_queue.put(('add_client', (sock, name)))
        server_gui.message_queue.put(('log', f"Connected from {addr} as '{name}'"))

        # loop to receive messages
        while True:
            header = recv_all(sock, 4)
            if not header:
                break
            (length,) = struct.unpack('!I', header)
            packet = recv_all(sock, length)
            if not packet:
                break

            valid, text = verify_and_extract(packet)
            if not valid:
                # send error back
                err_payload = make_packet(ERROR_TOKEN)
                err_payload = maybe_corrupt(err_payload)
                try:
                    sock.sendall(struct.pack('!I', len(err_payload)) + err_payload)
                except:
                    pass
                server_gui.message_queue.put(('log', f"CRC error from {name}; notified client."))
            else:
                # valid message -> show in server log (but do not broadcast to other clients)
                server_gui.message_queue.put(('received', (name, text)))
                # send ack back
                ack_payload = make_packet(f"Server received: {text}")
                ack_payload = maybe_corrupt(ack_payload)
                try:
                    sock.sendall(struct.pack('!I', len(ack_payload)) + ack_payload)
                    server_gui.message_queue.put(('sent', (name, f"ACK for message")))
                except:
                    pass
                if text.strip() == "[bye]":
                    break

    except Exception as e:
        server_gui.message_queue.put(('log', f"Exception for client {addr}: {e}"))
    finally:
        try:
            sock.close()
        except:
            pass
        server_gui.message_queue.put(('remove_client', sock))


def accept_loop(server_sock, gui: ServerGUI):
    while True:
        client_sock, client_addr = server_sock.accept()
        t = threading.Thread(target=client_thread, args=(client_sock, client_addr, gui), daemon=True)
        t.start()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    root = tk.Tk()
    gui = ServerGUI(root)

    # start accept thread
    t = threading.Thread(target=accept_loop, args=(srv, gui), daemon=True)
    t.start()

    gui._append_log(f"Server listening on {HOST}:{PORT}")
    root.mainloop()
    try:
        srv.close()
    except:
        pass

if __name__ == "__main__":
    main()
