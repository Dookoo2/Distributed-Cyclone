#!/usr/bin/env python3
import asyncio
import aiosqlite
import os
import sys
import signal
import atexit
import subprocess
import datetime
import argparse

DB_NAME = "database.db"
LOG_FILE = "log.txt"
FOUND_FILE = "found.txt"
BLOCK_FILE = "block.txt"
REQUEST_KEYWORD = "get range"
TARGET_KEYWORD = "get target"
NOT_FOUND_MARKER = " NOT FOUND"
FOUND_MARKER = " FOUND "
NOT_COMPUTED_MARKER = " NOT COMPUTED"
HOST = "0.0.0.0"
PORT = 12345
PROTOCOL = "tcp"
file_lock = asyncio.Lock()
stats_lock = asyncio.Lock()
console_lock = asyncio.Lock()
db_lock = asyncio.Lock()
connected_clients = 0
computed_ranges = 0
computing_ranges = 0
found_key = None
db = None
status_is_first = True
status_lines_count = 0

def log_event(msg):
    t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{t}] {msg}\n")

def block_log(msg):
    t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(BLOCK_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{t}] {msg}\n")

async def db_log(event):
    try:
        async with db_lock:
            await db.execute("INSERT INTO log (event_time, event) VALUES(?, ?)", (datetime.datetime.now(), event))
            await db.commit()
    except Exception as e:
        # Если логирование в БД не удалось, пишем в файл
        log_event(f"DB log error: {e}")

async def block_ip_for_8h(ip):
    try:
        await asyncio.to_thread(subprocess.run, ["sudo", "ufw", "deny", "from", ip],
                                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        block_log(f"[!] Blocked {ip} for 8h")
        async with db_lock:
            await db.execute("INSERT INTO blocked (ip,blocked_time) VALUES(?,?)", (ip, datetime.datetime.now()))
            await db.commit()
        asyncio.create_task(unblock_after_8h(ip))
    except Exception as e:
        block_log(f"[!] Block fail {ip}: {e}")

async def unblock_after_8h(ip):
    await asyncio.sleep(8 * 3600)
    try:
        await asyncio.to_thread(subprocess.run, ["sudo", "ufw", "delete", "deny", "from", ip],
                                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        block_log(f"[!] Unblocked {ip} after 8h")
        async with db_lock:
            await db.execute("DELETE FROM blocked WHERE ip=?", (ip,))
            await db.commit()
    except Exception as e:
        block_log(f"[!] Unblock fail {ip}: {e}")

async def cleanup_blocked():
    async with db_lock:
        c = await db.execute("SELECT DISTINCT ip FROM blocked")
        ips = await c.fetchall()
        await c.close()
        for row in ips:
            ip = row[0]
            try:
                subprocess.run(["sudo", "ufw", "delete", "deny", "from", ip],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                block_log(f"[!] Unblocked {ip} on exit")
            except Exception as e:
                block_log(f"[!] Unblock fail {ip} on exit: {e}")
        await db.execute("DELETE FROM blocked")
        await db.commit()

def enable_port():
    try:
        subprocess.run(["sudo", "ufw", "allow", f"{PORT}/{PROTOCOL}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event(f"[+] Port {PORT}/{PROTOCOL} opened")
    except Exception as e:
        log_event(f"[!] Port open err: {e}")
        sys.exit(1)

def disable_port():
    try:
        subprocess.run(["sudo", "ufw", "delete", "allow", f"{PORT}/{PROTOCOL}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event(f"[+] Port {PORT}/{PROTOCOL} closed")
    except Exception as e:
        log_event(f"[!] Port close err: {e}")

async def get_remain():
    async with db_lock:
        c = await db.execute("SELECT COUNT(*) FROM ranges WHERE status='pending'")
        r = await c.fetchone()
        await c.close()
    return r[0]

async def get_blocked():
    async with db_lock:
        c = await db.execute("SELECT COUNT(DISTINCT ip) FROM blocked")
        r = await c.fetchone()
        await c.close()
    return r[0]

async def print_status():
    global status_is_first, status_lines_count, connected_clients, computed_ranges, computing_ranges, found_key
    rem = await get_remain()
    blk = await get_blocked()
    lines = [
        "========= Cyclone server status =========",
        f"Clients  : {connected_clients}",
        f"Computed : {computed_ranges}",
        f"Computing: {computing_ranges}",
        f"Remain   : {rem}",
        f"Blocked  : {blk}",
        f"Found key: {found_key if found_key else 'None'}",
        "========================================="
    ]
    async with console_lock:
        if not status_is_first:
            sys.stdout.write("\033[F" * status_lines_count)
            for _ in range(status_lines_count):
                sys.stdout.write("\033[K\n")
            sys.stdout.write("\033[F" * status_lines_count)
        for ln in lines:
            print(ln)
        sys.stdout.flush()
    status_lines_count = len(lines)
    status_is_first = False

async def handle_client(reader, writer):
    global connected_clients, computed_ranges, computing_ranges, found_key
    addr = writer.transport.get_extra_info("peername")
    await db_log(f"Client connected: {addr}")
    async with stats_lock:
        connected_clients += 1
    await print_status()
    last_alive = datetime.datetime.now()
    current = None
    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=45)
            except asyncio.TimeoutError:
                now = datetime.datetime.now()
                if (now - last_alive).total_seconds() > (480 * 60):
                    log_event(f"[!] {addr} no ALIVE>8h")
                    await db_log(f"Client {addr} timeout (no ALIVE)")
                    break
                continue
            if not line:
                break
            req = line.decode("utf-8", errors="ignore").strip()
            if not req:
                continue
            if req != "ALIVE":
                await db_log(f"From {addr}: {req}")
            if req == "ALIVE":
                last_alive = datetime.datetime.now()
                continue
            if req == TARGET_KEYWORD:
                async with db_lock:
                    c = await db.execute("SELECT address FROM ranges LIMIT 1")
                    row = await c.fetchone()
                    await c.close()
                t = row[0] if row else "NO TARGET"
                try:
                    writer.write((t + "\n").encode("utf-8"))
                    await writer.drain()
                except:
                    pass
                continue
            if req == REQUEST_KEYWORD:
                s, e = None, None
                async with db_lock:
                    c = await db.execute("SELECT start,end FROM ranges WHERE status='pending' ORDER BY RANDOM() LIMIT 1")
                    row = await c.fetchone()
                    if row:
                        s, e = row
                        await db.execute("UPDATE ranges SET status='computing' WHERE start=? AND end=?", (s, e))
                        await db.commit()
                if s and e:
                    current = {"start": s, "end": e}
                    async with stats_lock:
                        computing_ranges += 1
                    try:
                        writer.write(f"{s}:{e}\n".encode("utf-8"))
                        await writer.drain()
                        await print_status()
                    except:
                        async with db_lock:
                            await db.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?", (s, e))
                            await db.commit()
                        async with stats_lock:
                            computing_ranges -= 1
                        current = None
                else:
                    try:
                        writer.write(b"NO RANGE\n")
                        await writer.drain()
                    except:
                        pass
                continue
            if req.endswith(NOT_COMPUTED_MARKER):
                val = req.rsplit(NOT_COMPUTED_MARKER, 1)[0].strip()
                seg_s, seg_e = None, None
                if ":" in val:
                    seg_s, seg_e = val.split(":", 1)
                elif current:
                    seg_s, seg_e = current["start"], current["end"]
                if seg_s and seg_e:
                    async with db_lock:
                        await db.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?", (seg_s, seg_e))
                        await db.commit()
                async with stats_lock:
                    computing_ranges -= 1
                current = None
                await print_status()
                continue
            if FOUND_MARKER in req:
                parts = req.split(FOUND_MARKER, 1)
                k = parts[1].strip() if len(parts) >= 2 else None
                if k:
                    async with file_lock:
                        with open(FOUND_FILE, "a", encoding="utf-8") as ff:
                            ff.write(k + "\n")
                    async with db_lock:
                        await db.execute("INSERT INTO found (found_key,found_time) VALUES(?,?)", (k, datetime.datetime.now()))
                        await db.commit()
                    pref = parts[0].strip()
                    if ":" in pref:
                        seg_s, seg_e = pref.split(":", 1)
                        async with db_lock:
                            await db.execute("UPDATE ranges SET status='done' WHERE start=? AND end=?", (seg_s, seg_e))
                            await db.commit()
                    async with stats_lock:
                        computing_ranges -= 1
                        computed_ranges += 1
                        found_key = k
                    current = None
                    await print_status()
                continue
            if req.endswith(NOT_FOUND_MARKER):
                val = req.rsplit(NOT_FOUND_MARKER, 1)[0].strip()
                seg_s, seg_e = None, None
                if ":" in val:
                    seg_s, seg_e = val.split(":", 1)
                elif current:
                    seg_s, seg_e = current["start"], current["end"]
                if seg_s and seg_e:
                    async with db_lock:
                        await db.execute("UPDATE ranges SET status='done' WHERE start=? AND end=?", (seg_s, seg_e))
                        await db.commit()
                    async with stats_lock:
                        computing_ranges -= 1
                        computed_ranges += 1
                current = None
                await print_status()
                continue
            await block_ip_for_8h(addr[0])
            return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        if current:
            async with db_lock:
                await db.execute("UPDATE ranges SET status='pending' WHERE start=? AND end=?", (current["start"], current["end"]))
                await db.commit()
            async with stats_lock:
                computing_ranges -= 1
        async with stats_lock:
            connected_clients -= 1
        await db_log(f"Client disconnected: {addr}")
        await print_status()

def sig_handler(*_):
    log_event("[!] SIGINT shutting down")
    sys.exit(0)

@atexit.register
def on_exit():
    try:
        asyncio.run(cleanup_blocked())
    except:
        pass
    disable_port()

async def main_server():
    s = await asyncio.start_server(handle_client, HOST, PORT)
    log_event(f"[i] Server on {HOST}:{PORT}")
    await print_status()
    async with s:
        await s.serve_forever()

def daemonize():
    if os.fork() != 0:
        sys.exit(0)
    os.setsid()
    if os.fork() != 0:
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    with open("/dev/null", "rb") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open("/dev/null", "ab") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())

async def init_db():
    global db, computed_ranges, computing_ranges
    db_exists = os.path.exists(DB_NAME) and os.path.getsize(DB_NAME) > 0
    db = await aiosqlite.connect(DB_NAME)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("CREATE TABLE IF NOT EXISTS ranges(id INTEGER PRIMARY KEY, start TEXT, end TEXT, address TEXT, status TEXT)")
    await db.execute("CREATE TABLE IF NOT EXISTS blocked(id INTEGER PRIMARY KEY, ip TEXT, blocked_time TIMESTAMP)")
    await db.execute("CREATE TABLE IF NOT EXISTS found(id INTEGER PRIMARY KEY, found_key TEXT, found_time TIMESTAMP)")
    await db.execute("CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, event_time TIMESTAMP, event TEXT)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_st ON ranges(status)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_se ON ranges(start, end)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_addr ON ranges(address)")
    await db.commit()
    if db_exists:
        r = input(f"Database '{DB_NAME}' exists. Use it (Y) or new (N)? [Y/N]: ").strip().lower()
        use_existing = r in ["y", "yes"]
    else:
        use_existing = False
    if not use_existing:
        await db.execute("DELETE FROM ranges")
        await db.commit()
        computed_ranges = 0
        computing_ranges = 0
        s = input("Enter start hex: ").strip()
        e = input("Enter end hex: ").strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        if e.lower().startswith("0x"):
            e = e[2:]
        try:
            si = int(s, 16)
            ei = int(e, 16)
        except:
            print("Invalid hex")
            sys.exit(1)
        if si > ei:
            print("Swapping start/end")
            si, ei = ei, si
        try:
            segs = int(input("Enter segments: ").strip())
        except:
            print("Bad segments")
            sys.exit(1)
        if segs <= 0:
            print("Segments>0")
            sys.exit(1)
        t = input("Enter target address: ").strip()
        tot = ei - si + 1
        if segs > tot:
            print(f"Too big {segs} > {tot}, adjusting")
            segs = tot
        base = tot // segs
        rem = tot % segs
        cur = si
        records = []
        for i in range(segs):
            ss = base + (1 if i < rem else 0)
            st = cur
            en = cur + ss - 1
            cur = en + 1
            stx = format(st, "X")
            enx = format(en, "X")
            records.append((stx, enx, t, "pending"))
        await db.executemany("INSERT INTO ranges(start, end, address, status) VALUES(?,?,?,?)", records)
        await db.commit()
        log_event(f"New DB {s}-{e} segs={segs} target={t}")
        await db_log(f"New DB created: {s}-{e} segs={segs} target={t}")
    else:
        await db.execute("UPDATE ranges SET status='pending' WHERE status='computing'")
        await db.commit()
        log_event("Existing DB reused, computing->pending")
        await db_log("Existing DB reused, computing->pending")
        c = await db.execute("SELECT COUNT(*) FROM ranges WHERE status='done'")
        row = await c.fetchone()
        computed_ranges = row[0] if row else 0
        computing_ranges = 0
        await c.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    signal.signal(signal.SIGINT, sig_handler)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(init_db())
    enable_port()
    if args.daemon:
        daemonize()
    loop.run_until_complete(main_server())

if __name__ == "__main__":
    main()
