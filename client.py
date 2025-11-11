# client.py
import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import random
from crc import make_packet, verify_and_extract

SERVER_PORT = 1234
SIMULATED_ERROR_RATE = 0.10  # 10% chance to flip a bit on send
ERROR_TOKEN = '__CRC_ERROR__'

def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf

def maybe_corrupt(payload: bytes) -> bytes:
    if random.random() < SIMULATED_ERROR_RATE and len(payload) > 0:
        b_idx = random.randrange(len(payload))
        bit = 1 << random.randrange(8)
        corrupted = bytearray(payload)
        corrupted[b_idx] ^= bit
        return bytes(corrupted)
    return payload

class ClientGUI:
    def __init__(self, root):
        self.root = root
        root.title("Client - Chat with Server (GUI)")
        root.geometry("520x480")

        topfrm = ttk.Frame(root, padding=6)
        topfrm.pack(fill=tk.X)

        ttk.Label(topfrm, text="Server IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(topfrm, width=15)
        self.ip_entry.pack(side=tk.LEFT, padx=4)
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Label(topfrm, text="Your name:").pack(side=tk.LEFT, padx=(8,0))
        self.name_entry = ttk.Entry(topfrm, width=12)
        self.name_entry.pack(side=tk.LEFT, padx=4)
        self.name_entry.insert(0, "Client1")

        self.connect_btn = ttk.Button(topfrm, text="Connect", command=self.connect)
        self.connect_btn.pack(side=tk.LEFT, padx=6)

        self.chat = scrolledtext.ScrolledText(root, state='disabled', height=20)
        self.chat.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        botfrm = ttk.Frame(root, padding=6)
        botfrm.pack(fill=tk.X)

        self.msg_entry = ttk.Entry(botfrm)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.send_btn = ttk.Button(botfrm, text="Send", command=self.send_message, state='disabled')
        self.send_btn.pack(side=tk.LEFT, padx=4)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.sock = None
        self.recv_thread = None
        self.connected = False

    def log(self, text):
        self.chat.config(state='normal')
        self.chat.insert(tk.END, text + "\n")
        self.chat.yview(tk.END)
        self.chat.config(state='disabled')

    def connect(self):
        if self.connected:
            messagebox.showinfo("Info", "Already connected")
            return
        server_ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        if not server_ip or not name:
            messagebox.showerror("Error", "Enter server IP and your name")
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server_ip, SERVER_PORT))
            # send name packet immediately (length-prefixed payload+crc)
            name_packet = make_packet(name)
            name_packet = maybe_corrupt(name_packet)
            self.sock.sendall(struct.pack('!I', len(name_packet)) + name_packet)

            self.connected = True
            self.connect_btn.config(state='disabled')
            self.send_btn.config(state='normal')
            self.log(f"Connected to {server_ip}:{SERVER_PORT} as '{name}'")

            self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
            self.recv_thread.start()
        except Exception as e:
            messagebox.showerror("Connect error", str(e))
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
            self.sock = None

    def send_message(self):
        if not self.connected or not self.sock:
            return
        text = self.msg_entry.get().strip()
        if not text:
            return
        try:
            payload = make_packet(text)
            payload = maybe_corrupt(payload)
            self.sock.sendall(struct.pack('!I', len(payload)) + payload)
            self.log(f"You → {text}")
            self.msg_entry.delete(0, tk.END)
            if text == "[bye]":
                # After sending bye, optionally close after server ack
                pass
        except Exception as e:
            self.log(f"Send failed: {e}")
            try:
                self.sock.close()
            except:
                pass
            self.connected = False
            self.connect_btn.config(state='normal')
            self.send_btn.config(state='disabled')

    def recv_loop(self):
        try:
            while True:
                header = recv_all(self.sock, 4)
                if not header:
                    break
                (length,) = struct.unpack('!I', header)
                packet = recv_all(self.sock, length)
                if not packet:
                    break
                valid, text = verify_and_extract(packet)
                if not valid:
                    # server indicated that the message we sent got corrupted or server response corrupted
                    self.log("⚠ Error detected in received message (CRC mismatch).")
                else:
                    if text == ERROR_TOKEN:
                        # server told us our sent message was corrupted
                        self.log("⚠ Server reports: your last message was corrupted (CRC). Please resend.")
                    else:
                        self.log(f"Server → {text}")
                        # optionally if server says goodbye, close
                # continue
        except Exception as e:
            self.log(f"Receive loop error: {e}")
        finally:
            self.connected = False
            try:
                self.sock.close()
            except:
                pass
            self.connect_btn.config(state='normal')
            self.send_btn.config(state='disabled')
            self.log("Disconnected from server.")

    def on_close(self):
        try:
            if self.sock:
                try:
                    # attempt graceful bye
                    payload = make_packet("[bye]")
                    payload = maybe_corrupt(payload)
                    self.sock.sendall(struct.pack('!I', len(payload)) + payload)
                except:
                    pass
                try:
                    self.sock.close()
                except:
                    pass
        finally:
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
