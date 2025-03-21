# Server side of Distributed Cyclone software. Tested on Ubuntu 24.04.
#!/usr/bin/env python3
import socket
import threading
import sqlite3
import os
import datetime
import sys
import signal
import atexit
import subprocess
import select
import time

REQUEST_KEYWORD = "get range"
TARGET_KEYWORD = "get target"
NOT_FOUND_MARKER = " NOT FOUND"
FOUND_MARKER = " FOUND "
NOT_COMPUTED_MARKER = " NOT COMPUTED"

DB_NAME = "database.db"
LOG_FILE = "log.txt"
FOUND_FILE = "found.txt"

file_lock = threading.Lock()
stats_lock = threading.Lock()
console_lock = threading.Lock()
global_db_lock = threading.Lock()

connected_clients = 0
computed_ranges = 0  
computing_ranges = 0
found_key = None
is_first_status_print = True

################################################################################
# Optional blocking/unblocking in ufw for unknown requests
################################################################################
def block_ip_for_8_hours(ip: str):
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True, stderr=subprocess.DEVNULL)
        log_event(f"[!] IP {ip} has been blocked in ufw for 8 hours (invalid request)")
        t = threading.Thread(target=_unblock_after_8h, args=(ip,))
        t.daemon = True
        t.start()
    except Exception as e:
        log_event(f"[!] Could not block IP {ip} in ufw: {e}")

def _unblock_after_8h(ip: str):
    time.sleep(8 * 3600)
    try:
        subprocess.run(["sudo", "ufw", "delete", "deny", "from", ip], check=True, stderr=subprocess.DEVNULL)
        log_event(f"[!] IP {ip} has been unblocked in ufw after 8 hours")
    except Exception as e:
        log_event(f"[!] Could not unblock IP {ip}: {e}")

def log_event(message: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with file_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")

def get_remaining_segments() -> int:
    with global_db_lock:
        cur = global_db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ranges WHERE status='pending'")
        count = cur.fetchone()[0]
        cur.close()
    return count

def print_status():
    global is_first_status_print, connected_clients, computed_ranges, computing_ranges, found_key
    remaining = get_remaining_segments()
    lines = [
        "======Cyclone server status======",
        f"Clients  : {connected_clients}",
        f"Computed : {computed_ranges}",
        f"Computing: {computing_ranges}",
        f"Remain   : {remaining}",
        f"Found key: {found_key if found_key else 'None'}",
        "================================="
    ]
    with console_lock:
        if not is_first_status_print:
            sys.stdout.write("\033[F" * len(lines))
            for _ in lines:
                sys.stdout.write("\033[K\n")
            sys.stdout.write("\033[F" * len(lines))
        for line in lines:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()
    is_first_status_print = False

HOST = '0.0.0.0'
PORT = 12345
PROTOCOL = 'tcp'

def enable_port():
    try:
        subprocess.run(["sudo", "ufw", "allow", f"{PORT}/{PROTOCOL}"], check=True, stderr=subprocess.DEVNULL)
        log_event(f"[+] Port {PORT}/{PROTOCOL} is open")
        print("Port was opened")
    except Exception as e:
        log_event(f"[!] Error opening port: {e}")
        sys.exit(1)

def disable_port():
    try:
        subprocess.run(["sudo", "ufw", "delete", "allow", f"{PORT}/{PROTOCOL}"], check=True, stderr=subprocess.DEVNULL)
        log_event(f"[+] Port {PORT}/{PROTOCOL} is closed")
    except Exception as e:
        log_event(f"[!] Error closing port: {e}")

db_exists = os.path.exists(DB_NAME)
db_nonempty = db_exists and os.path.getsize(DB_NAME) > 0

if db_exists and db_nonempty:
    choice = input(f"Database '{DB_NAME}' already exists. Use it (Y) or create new (N)? [Y/N]: ").strip().lower()
    use_existing = choice in ['y', 'yes']
else:
    use_existing = False

global_db_conn = sqlite3.connect(DB_NAME, check_same_thread=False)
global_db_conn.execute("PRAGMA journal_mode=WAL")

with global_db_lock:
    cur = global_db_conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start TEXT,
            end TEXT,
            address TEXT,
            status TEXT
        )
    """)
    global_db_conn.commit()

    cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON ranges(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_start_end ON ranges(start, end)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_address ON ranges(address)")
    global_db_conn.commit()

    if not use_existing:
        cur.execute("DELETE FROM ranges")
        global_db_conn.commit()

        start_hex = input("Enter start of range (HEX): ").strip()
        end_hex = input("Enter end of range (HEX): ").strip()

        if start_hex.lower().startswith("0x"):
            start_hex = start_hex[2:]
        if end_hex.lower().startswith("0x"):
            end_hex = end_hex[2:]

        try:
            start_int = int(start_hex, 16)
            end_int = int(end_hex, 16)
        except ValueError as e:
            print(f"Invalid HEX value: {e}")
            cur.close()
            global_db_conn.close()
            sys.exit(1)

        if start_int > end_int:
            print("Start is greater than end; swapping values.")
            start_int, end_int = end_int, start_int
            start_hex, end_hex = end_hex, start_hex

        try:
            segments = int(input("Enter number of segments (DEC): ").strip())
        except ValueError:
            print("Invalid number of segments.")
            cur.close()
            global_db_conn.close()
            sys.exit(1)

        if segments <= 0:
            print("Number of segments must be positive.")
            cur.close()
            global_db_conn.close()
            sys.exit(1)

        target_address = input("Enter target P2PKH address: ").strip()
        total_values = end_int - start_int + 1
        if segments > total_values:
            print(f"Segments ({segments}) exceed total values ({total_values}). Adjusting segments to {total_values}.")
            segments = total_values

        base_size = total_values // segments
        remainder = total_values % segments
        curr_start = start_int

        for i in range(segments):
            seg_size = base_size + (1 if i < remainder else 0)
            seg_start_int = curr_start
            seg_end_int = curr_start + seg_size - 1
            curr_start = seg_end_int + 1
            seg_start_hex = format(seg_start_int, 'X')
            seg_end_hex = format(seg_end_int, 'X')
            cur.execute("INSERT INTO ranges (start, end, address, status) VALUES (?, ?, ?, ?)",
                        (seg_start_hex, seg_end_hex, target_address, "pending"))

        global_db_conn.commit()
        log_event(f"New database initialized. Range {start_hex}-{end_hex} with {segments} segments. Target: {target_address}")
    else:
        cur.execute("UPDATE ranges SET status='pending' WHERE status='computing'")
        global_db_conn.commit()
        log_event("Existing database loaded. All 'computing' segments reset to 'pending'.")

        with stats_lock:
            cur.execute("SELECT COUNT(*) FROM ranges WHERE status='done'")
            computed_ranges = cur.fetchone()[0]

    cur.close()

def get_db_connection():
    c = sqlite3.connect(DB_NAME, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    return c

def handle_client(client_sock: socket.socket, client_addr):
    global connected_clients, computed_ranges, computing_ranges, found_key
    local_db_conn = get_db_connection()
    current_segment = None
    last_alive = datetime.datetime.now()

    data_buffer = b""

    try:
        while True:
            ready, _, _ = select.select([client_sock], [], [], 45)
            if ready:
                chunk = b""
                try:
                    chunk = client_sock.recv(1024)
                except Exception as e:
                    log_event(f"[!] Error reading from {client_addr}: {e}")

                if not chunk:
                    # Client disconnected
                    break

                data_buffer += chunk

                while b'\n' in data_buffer:
                    line, data_buffer = data_buffer.split(b'\n', 1)
                    req = line.decode('utf-8', errors='ignore').strip()

                    if not req:
                        continue

                    log_event(f"[>] Received from {client_addr}: {req}")

                    if req == "ALIVE":
                        last_alive = datetime.datetime.now()
                        continue

                    if req.endswith(NOT_COMPUTED_MARKER):
                        val = req.rsplit(NOT_COMPUTED_MARKER, 1)[0].strip()
                        if ':' in val:
                            seg_start, seg_end = val.split(':', 1)
                        elif current_segment is not None:
                            seg_start = current_segment['start']
                            seg_end = current_segment['end']
                        else:
                            seg_start = seg_end = None
                        if seg_start and seg_end:
                            with local_db_conn:
                                c = local_db_conn.cursor()
                                c.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?",
                                          (seg_start, seg_end))
                                c.close()
                            log_event(f"[>] Range {seg_start}:{seg_end} -> pending (NOT COMPUTED)")
                        with stats_lock:
                            computing_ranges -= 1
                        current_segment = None
                        print_status()
                        continue

                    if req == TARGET_KEYWORD:
                        with local_db_conn:
                            c = local_db_conn.cursor()
                            c.execute("SELECT address FROM ranges LIMIT 1")
                            r = c.fetchone()
                            tgt = r[0] if r else "NO TARGET"
                            c.close()
                        try:
                            client_sock.sendall((tgt + "\n").encode('utf-8'))
                        except Exception as e:
                            log_event(f"[!] Error sending target address: {e}")
                        log_event(f"[<] Sent (target): {tgt}")
                        continue

                    if FOUND_MARKER in req:
                        # No server response is sent here after FOUND
                        parts = req.split(FOUND_MARKER)
                        if len(parts) >= 2:
                            key = parts[1].strip()
                            with file_lock:
                                with open(FOUND_FILE, "a", encoding="utf-8") as ff:
                                    ff.write(key + "\n")
                            if ':' in parts[0]:
                                seg_s, seg_e = parts[0].strip().split(':', 1)
                                with local_db_conn:
                                    c = local_db_conn.cursor()
                                    c.execute("UPDATE ranges SET status='done' WHERE start=? AND end=?",
                                              (seg_s, seg_e))
                                    c.close()
                            with stats_lock:
                                computing_ranges -= 1
                                computed_ranges += 1
                                found_key = key
                            current_segment = None
                            print_status()
                        continue

                    if req.endswith(NOT_FOUND_MARKER):
                        val = req.rsplit(NOT_FOUND_MARKER, 1)[0].strip()
                        if ':' in val:
                            seg_start, seg_end = val.split(':', 1)
                        elif current_segment is not None:
                            seg_start = current_segment['start']
                            seg_end = current_segment['end']
                        else:
                            seg_start = seg_end = None
                        if seg_start and seg_end:
                            with local_db_conn:
                                c = local_db_conn.cursor()
                                c.execute("UPDATE ranges SET status='done' WHERE start=? AND end=?",
                                          (seg_start, seg_end))
                                c.close()
                            log_event(f"[>] Range {seg_start}:{seg_end} done (NOT FOUND)")
                        with stats_lock:
                            computing_ranges -= 1
                            computed_ranges += 1
                        current_segment = None
                        print_status()
                        continue

                    if req == REQUEST_KEYWORD:
                        with local_db_conn:
                            c = local_db_conn.cursor()
                            c.execute("SELECT start, end FROM ranges WHERE status='pending' ORDER BY RANDOM() LIMIT 1")
                            row = c.fetchone()
                            if row:
                                seg_start, seg_end = row
                                c.execute("UPDATE ranges SET status='computing' WHERE start=? AND end=?",
                                          (seg_start, seg_end))
                                current_segment = {"start": seg_start, "end": seg_end}
                                with stats_lock:
                                    computing_ranges += 1
                            else:
                                current_segment = None
                            c.close()

                        if current_segment:
                            try:
                                msg = f"{current_segment['start']}:{current_segment['end']}\n"
                                client_sock.sendall(msg.encode('utf-8'))
                                log_event(f"[<] Issued {msg.strip()} to {client_addr}")
                                print_status()
                            except Exception as e:
                                log_event(f"[!] Error sending range: {e}")
                                with local_db_conn:
                                    c = local_db_conn.cursor()
                                    c.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?",
                                              (current_segment['start'], current_segment['end']))
                                    c.close()
                                with stats_lock:
                                    computing_ranges -= 1
                                current_segment = None
                        else:
                            try:
                                client_sock.sendall("NO RANGE\n".encode('utf-8'))
                            except Exception as e:
                                log_event(f"[!] Error sending NO RANGE: {e}")
                        continue

                    # Unknown request -> for example, block or just log
                    else:
                        log_event(f"[!] Unknown request from {client_addr}: {req}")
                        # block_ip_for_8_hours(client_addr[0])  # if you want to block
                        continue
            else:
                now = datetime.datetime.now()
                if (now - last_alive).total_seconds() > 480*60:
                    log_event(f"[!] {client_addr} disconnected: no ALIVE for 8 hours")
                    break
                continue

    except Exception as e:
        log_event(f"[!] Exception in handler for {client_addr}: {e}")

    finally:
        try:
            client_sock.close()
        except Exception as e:
            log_event(f"[!] Error closing socket {client_addr}: {e}")
        if current_segment is not None:
            with local_db_conn:
                c = local_db_conn.cursor()
                c.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?",
                          (current_segment['start'], current_segment['end']))
                c.close()
            log_event(f"[!] Range {current_segment['start']}:{current_segment['end']} returned to 'pending'")
            with stats_lock:
                computing_ranges -= 1
            current_segment = None
        with stats_lock:
            connected_clients -= 1
        print_status()
        local_db_conn.close()

def signal_handler(sig, frame):
    log_event("Shutting down server...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
atexit.register(disable_port)

enable_port()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(128)
    log_event(f"[i] Server running on {HOST}:{PORT}")
    print_status()

    while True:
        try:
            conn, addr = s.accept()
            log_event(f"[+] Connection from {addr[0]}:{addr[1]}")
            with stats_lock:
                connected_clients += 1
            print_status()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.start()
        except Exception as e:
            log_event(f"[!] Accept error: {e}")
