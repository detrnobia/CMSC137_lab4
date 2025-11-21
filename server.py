
import socket
import threading
import struct
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext
from crc import makePacket, verifyPacket, ERROR_TOKEN

#server listens on all interfaces at this port
HOST = "0.0.0.0"
PORT = 1234

#reads exaclty n bytes from a blocking socket
def recv_all(sock, n):
    """Receive exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf

#creates gui layout
class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Server Chat")

        frame = ttk.Frame(root, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)

        # LEFT LOG WINDOW (server chat + client chat + notices)
        left = ttk.Frame(frame)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(left, text="Chat Log").pack(anchor=tk.W)
        self.log = scrolledtext.ScrolledText(left, state="disabled", height=20)
        self.log.pack(fill=tk.BOTH, expand=True)

        # RIGHT CLIENT LIST
        right = ttk.Frame(frame)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(right, text="Connected Clients").pack(anchor=tk.W)
        self.clients_list = tk.Listbox(right, height=12)
        self.clients_list.pack(fill=tk.X)

        # SERVER SEND MESSAGE UI
        bottom = ttk.Frame(root, padding=8)
        bottom.pack(fill=tk.X)

        self.server_msg = ttk.Entry(bottom)
        self.server_msg.pack(side=tk.LEFT, fill=tk.X, expand=True)

        send_btn = ttk.Button(bottom, text="Send", command=self.send_server_message)
        send_btn.pack(side=tk.LEFT, padx=6)

        # State: clients + queue
        self.clients = {} #map sockets
        self.clients_lock = threading.Lock() 
        self.queue = queue.Queue()

        # Begin queue processor;runs every 100ms
        self.root.after(100, self.process_queue)

    def log_msg(self, text):
        """Display text in server log/chat window."""
        self.log.config(state="normal")
        self.log.insert(tk.END, text + "\n")
        self.log.yview(tk.END)
        self.log.config(state="disabled")

    def send_server_message(self):
        """Server sends a chat message."""
        msg = self.server_msg.get().strip()
        if msg == "":
            return

        formatted = f"[Server] {msg}"
        self.log_msg(formatted)          # <-- display server chat locally
        self.broadcast(formatted)        # <-- send to all clients
        self.server_msg.delete(0, tk.END)

    #bridge between worker threads and GUI
    def process_queue(self):
        """Handle queued events from client threads."""
        while not self.queue.empty():
            event, data = self.queue.get()

            if event == "log":
                self.log_msg(data)

            elif event == "client_chat":
                # Show client chat messages in server chat window!
                self.log_msg(data)

            elif event == "broadcast":
                self.broadcast(data)

            elif event == "add_client":
                sock, name = data
                with self.clients_lock:
                    self.clients[sock] = name
                self.clients_list.insert(tk.END, name)
                self.log_msg(f"[Server Notice] {name} connected.")

            elif event == "remove_client":
                sock = data
                with self.clients_lock:
                    name = self.clients.pop(sock, None)

                if name:
                    try:
                        idx = self.clients_list.get(0, tk.END).index(name)
                        self.clients_list.delete(idx)
                    except:
                        pass
                    self.log_msg(f"[Server Notice] {name} disconnected.")

        self.root.after(100, self.process_queue)

    def broadcast(self, text):
        """Broadcast message to all clients."""
        packet = makePacket(text) #wraps text with crc

        with self.clients_lock:
            items = list(self.clients.items())

        for sock, _ in items:
            try:
                #sends s4-byte length header,crc-secured packet
                sock.sendall(struct.pack("!I", len(packet)) + packet)
            except:
                pass

#every connected client runs its own thread
def client_thread(sock, addr, gui: ServerGUI):
    try:
        # Receive client's NAME
        header = recv_all(sock, 4)
        if not header:
            return
        #read packet
        (length,) = struct.unpack("!I", header)
        packet = recv_all(sock, length)
        #verify crc,extract name
        valid, name = verifyPacket(packet)
        if not valid:
            name = "Unknown"
        #server triggers
        gui.queue.put(("add_client", (sock, name)))
        # Broadcast enter
        gui.queue.put(("broadcast", f"{name} has entered the chat. Welcome!"))
        # Show enter in server GUI
        gui.queue.put(("client_chat", f"{name} has entered the chat. Welcome!"))

        last_request_resend = False

        # MAIN LOOP
        while True:
            header = recv_all(sock, 4)
            if not header:
                break

            (length,) = struct.unpack("!I", header)
            packet = recv_all(sock, length)
            if not packet:
                break

            valid, text = verifyPacket(packet)

            # handles corrupted messages
            if not valid:
                gui.queue.put(("log", f"[Server Notice] Corrupted message from {name}"))

                gui.queue.put(("broadcast",
                               f"[Server Notice] Received a corrupted message from {name}. Resend requested."))

                # Ask sender to resend
                err = makePacket(ERROR_TOKEN)
                try:
                    sock.sendall(struct.pack("!I", len(err)) + err)
                except:
                    pass

                last_request_resend = True
                continue

            # Ignore ERROR_TOKEN
            if text == ERROR_TOKEN:
                continue
            # CLEAN MESSAGE
            if last_request_resend:
                gui.queue.put(("log", f"{name} resent successfully."))
                last_request_resend = False

            formatted = f"{name} → {text}"

            # NEW FEATURE: show client chat message in server GUI
            gui.queue.put(("client_chat", formatted))

            gui.queue.put(("broadcast", formatted))

    finally:
        try:
            sock.close()
        except:
            pass

        gui.queue.put(("remove_client", sock))

        with gui.clients_lock:
            name = gui.clients.get(sock, "Unknown")

        gui.queue.put(("broadcast", f"{name} has left the chat."))
        gui.queue.put(("client_chat", f"{name} has left the chat."))


def accept_loop(server_sock, gui):
    while True:
        client, addr = server_sock.accept()
        threading.Thread(target=client_thread, args=(client, addr, gui), daemon=True).start()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    root = tk.Tk()
    gui = ServerGUI(root)
    gui.log_msg(f"[Server Notice] Server running on {HOST}:{PORT}")

    threading.Thread(target=accept_loop, args=(srv, gui), daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    main()
