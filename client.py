import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from crc import makePacket, verifyPacket, computeCRC, ERROR_TOKEN

SERVER_PORT = 1234


def getLocalIP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def receiveAll(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf


class ClientGUI:
    def __init__(self, root):
        self.root = root
        root.title("Client Chat")

        top = ttk.Frame(root, padding=6)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Server IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(top, width=15)
        self.ip_entry.pack(side=tk.LEFT)
        self.ip_entry.insert(0, getLocalIP())

        detect_btn = ttk.Button(top, text="Detect", command=self.detectLocalIP)
        detect_btn.pack(side=tk.LEFT, padx=(6,0))

        ttk.Label(top, text="Name:").pack(side=tk.LEFT, padx=(10, 2))
        self.name_entry = ttk.Entry(top, width=12)
        self.name_entry.pack(side=tk.LEFT)
        self.name_entry.insert(0, "Client1")

        self.connect_btn = ttk.Button(top, text="Connect", command=self.connect)
        self.connect_btn.pack(side=tk.LEFT, padx=6)

        self.chat = scrolledtext.ScrolledText(root, state="disabled", height=16)
        self.chat.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        bottom = ttk.Frame(root, padding=6)
        bottom.pack(fill=tk.X)
        self.msg_entry = ttk.Entry(bottom)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.send_btn = ttk.Button(bottom, text="Send", command=self.sendMessage, state="disabled")
        self.send_btn.pack(side=tk.LEFT, padx=4)

        self.sock = None
        self.connected = False
        self.last_message = None

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log(self, text):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, text + "\n")
        self.chat.yview(tk.END)
        self.chat.config(state="disabled")


    def connect(self):
        if self.connected:
            return

        ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        if not ip or not name:
            messagebox.showerror("Error", "Enter server IP and your name.")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, SERVER_PORT))

            payload = name.encode("utf-8")
            crc = computeCRC(payload)
            packet = payload + bytes([crc])
            self.sock.sendall(struct.pack("!I", len(packet)) + packet)

            self.connected = True
            self.connect_btn.config(state="disabled")
            self.send_btn.config(state="normal")

            threading.Thread(target=self.receiveMessageLoop, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))


    def detectLocalIP(self):
        ip = getLocalIP()
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        try:
            self.log(f"Detected local IP: {ip}")
        except:
            pass
        
    def sendMessage(self):
        if not self.connected:
            return

        text = self.msg_entry.get().strip()
        if not text:
            return

        try:
            packet = makePacket(text)
            self.sock.sendall(struct.pack("!I", len(packet)) + packet)
            self.last_message = text
            self.msg_entry.delete(0, tk.END)
        except:
            self.connected = False


    def receiveMessageLoop(self):
        try:
            while True:
                header = receiveAll(self.sock, 4)
                if not header:
                    break

                (length,) = struct.unpack("!I", header)
                packet = receiveAll(self.sock, length)
                if not packet:
                    break
                

                valid, text = verifyPacket(packet)

                if valid and text == ERROR_TOKEN:
                    if self.last_message:
                        packet = makePacket(self.last_message)
                        self.sock.sendall(struct.pack("!I", len(packet)) + packet)
                    continue


                if valid:
                    self.log(text)

        finally:
            self.connected = False
            try:
                self.sock.close()
            except:
                pass


    def on_close(self):
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()
