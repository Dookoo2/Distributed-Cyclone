# 🚀 Distributed Cyclone

Distributed Cyclone is a collaborative platform for tackling Satoshi puzzles. Instead of relying solely on brute force or expensive hardware, this project harnesses the power of distributed computing by dividing the workload among many participants.

**Approaches to Solving Satoshi Puzzles**

There are at least four strategies to approach the challenge:

1. **Develop New Algorithms**  
   Create innovative algorithms for computing public keys on the Secp256k1 curve. For example, significantly accelerating the group modular inversion algorithm could provide a breakthrough.
2. **Optimize Existing Implementations**  
   Enhance current solutions with low-level assembly optimizations. Note: I experimented with this approach and only achieved up to a 5% speed boost.
3. **Utilize Ready-Made Software with GPU Resources**  
   Deploy existing software solutions, investing tens or even hundreds of thousands of dollars in GPU rental or purchase.
4. **Form a Collaborative Network**  
   Gather a community of thousands to collectively work on the problem.

Distributed Cyclone follows the fourth approach, enabling a dedicated group to solve a specific puzzle through coordinated effort.

## ⚡ Key Features
Distributed Cyclone provides a robust solution that:

- **Distributes the Search Range:**  
  Splits the overall search interval into many smaller subranges.
- **Allocates Work to Clients:**  
  Assigns segments of the search range to clients and manages telemetry data to monitor progress.
- **Prevents Duplication:**  
  Ensures that the same subrange is never issued twice to different clients.
- **Randomizes Task Distribution:**  
  Ideally distributes subranges in a random order to maximize efficiency and avoid predictable patterns.

All these functionalities have been implemented in Distributed Cyclone.

> **Warning:** Distributed Cyclone is currently in beta. Extensive testing has been performed, but unforeseen bugs may still arise.

## 💎 Architecture
- **Server Component:**  
  Written in Python for ease of development, as ultimate speed is not critical.  
  **Note:** The server has been tested exclusively on Ubuntu 24.04. Please use this OS or modify the server script to integrate with UFW if necessary.

- **Client Component:**  
  Developed in C++ using the original Cyclone engine to ensure high performance and quality.

## ❓ How It Works
1. **Server Initialization:**  
   Run the server script. You will be prompted to enter:
   - The start of the overall search range.
   - The end of the search range.
   - The number of segments into which the search range should be divided.
   - The target P2PKH address.
   
   If a database already exists (e.g., due to a previous run), the script will ask whether to use the existing DB or create a new one. By default, the server listens on TCP port `12345` and binds to all available network interfaces (`0.0.0.0`).

2. **Client Startup:**  
   Launch the client with the command-line flags `-i <IP>` and `-p <PORT>` to connect to the server.

3. **Task Assignment:**  
   The client sends two requests to the server:
   - `get target` – to retrieve the target P2PKH address.
   - `get range` – to receive a subrange for the search.
   
   Once the subrange is received, the client begins its computation.

4. **Keep-Alive Communication:**  
   During operation, the client periodically sends `ALIVE` messages to notify the server that it is still processing its assigned range.

5. **Handling an Unsuccessful Search:**  
   If the client completes a subrange without finding the key, it sends a `NOT FOUND` message (including the subrange details) and immediately requests a new subrange with `get range`.

6. **Successful Key Discovery:**  
   Upon finding the key, the client sends a `FOUND` message along with the discovered key to the server.

7. **Logging and Notification:**  
   The server logs the found key in `found.txt` and displays it on the console. Additionally, the event is recorded in the server log (`log.txt`).

8. **Privacy of Computation Details:**  
   During the search, the subranges and any found keys are not displayed on the client's console. These details are visible only on the server.

## 🔷 Example outputs
Below is an example of Cyclone in action, solving a Satoshi puzzle:

**Client Side**
```bash
root@DESKTOP-BD9V01U:/mnt/e/VM# ./Dist_Cyclone -i 91.84.105.101 -p 12345
================= SRV COMMUNICATION =================
SRV ip-address       : 91.84.105.101
SRV port             : 12345
Connection status    : Established
================= WORK IN PROGRESS ==================
Target Address: 1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy
CPU Threads   : 16
Mkeys/s       : 0.02
Total Checked : 1287568
Elapsed Time  : 00:00:56
Progress      : 0.00 %
Total ranges  : 59
=================== FOUND MATCH! ====================
     The key was found and sent to the server!
```

**Server side**
```bash
root@v310427:/home/btc# python3 srv.py
Database 'database.db' already exists. Use it (Y) or create new (N)? [Y/N]: N
Enter start of range (HEX): 236FB600000000
Enter end of range (HEX): 236FB6FFFFFFFF
Enter number of segments (DEC): 100
Enter target P2PKH address: 1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy
Rules updated
Rules updated (v6)
Port was opened
======Cyclone server status======
Clients  : 0
Computed : 59
Computing: 0
Remain   : 41
Found key: 00000000000000000000000000000000000000000000000000236FB6D5AD1F43
=================================
```

**Server log.txt**
```bash
[2025-XX-XX 23:29:04] New database initialized. Range 236FB600000000-236FB6FFFFFFFF with 100 segments. Target: 1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy
[2025-XX-XX 23:29:05] [+] Port 12345/tcp is open
[2025-XX-XX 23:29:05] [i] Server running on 0.0.0.0:12345
[2025-XX-XX 23:29:07] [+] Connection from 85.198.104.195:2310
[2025-XX-XX 23:29:07] [>] Received from ('85.198.104.195', 2310): get target
[2025-XX-XX 23:29:07] [<] Sent (target): 1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy
[2025-XX-XX 23:29:07] [>] Received from ('85.198.104.195', 2310): get range
[2025-XX-XX 23:29:07] [<] Issued 236FB66E147AE3:236FB670A3D70B to ('85.198.104.195', 2310)
[2025-XX-XX 23:29:08] [>] Received from ('85.198.104.195', 2310): 236FB66E147AE3:236FB670A3D70B NOT FOUND
[2025-XX-XX 23:29:08] [>] Range 236FB66E147AE3:236FB670A3D70B done (NOT FOUND)
[2025-XX-XX 23:29:08] [>] Received from ('85.198.104.195', 2310): get range
[2025-XX-XX 23:29:08] [<] Issued 236FB663D70A3F:236FB666666667 to ('85.198.104.195', 2310)
[2025-XX-XX 23:29:09] [>] Received from ('85.198.104.195', 2310): 236FB663D70A3F:236FB666666667 NOT FOUND
[2025-XX-XX 23:29:09] [>] Range 236FB663D70A3F:236FB666666667 done (NOT FOUND)
[2025-XX-XX 23:29:09] [>] Received from ('85.198.104.195', 2310): get range
[2025-XX-XX 23:29:09] [<] Issued 236FB6570A3D72:236FB65999999A to ('85.198.104.195', 2310)
[2025-XX-XX 23:29:10] [>] Received from ('85.198.104.195', 2310): 236FB6570A3D72:236FB65999999A NOT FOUND
[2025-XX-XX 23:29:10] [>] Range 236FB6570A3D72:236FB65999999A done (NOT FOUND)
[2025-XX-XX 23:29:10] [>] Received from ('85.198.104.195', 2310): get range
[2025-XX-XX 23:29:10] [<] Issued 236FB65999999B:236FB65C28F5C3 to ('85.198.104.195', 2310)
[2025-XX-XX 23:29:11] [>] Received from ('85.198.104.195', 2310): 236FB65999999B:236FB65C28F5C3 NOT FOUND
[2025-XX-XX 23:29:11] [>] Range 236FB65999999B:236FB65C28F5C3 done (NOT FOUND)
...
[2025-XX-XX 23:30:04] [>] Received from ('85.198.104.195', 2310): 236FB6D47AE14B:236FB6D70A3D73 FOUND 00000000000000000000000000000000000000000000000000236FB6D5AD1F43

```


## 🛠️ Getting Started

To get started with Cyclone, clone the repository and follow the installation instructions:

```bash
## AVX2 ##
git clone https://github.com/Dookoo2/Distributed-Cyclone.git
cd Distributed_Cyclone_avx2
g++ -std=c++17 -Ofast -ffast-math -funroll-loops -ftree-vectorize -fstrict-aliasing -fno-semantic-interposition -fvect-cost-model=unlimited -fno-trapping-math -fipa-ra -fipa-modref -flto -fassociative-math -fopenmp -mavx2 -mbmi2 -madx -o Dist_Cyclone Dist_Cyclone.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp
```

## ✌️**TIPS**
BTC: bc1qtq4y9l9ajeyxq05ynq09z8p52xdmk4hqky9c8n

Or connect to my server and let it run for a couple of days: **./Dist_Cyclone -i 91.84.105.101 -p 12345**
