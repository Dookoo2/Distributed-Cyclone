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
  
  **Hardware requirements:** 1 vCPU, 2Gb RAM, 40 GB SSD, Inet access. 
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
root@ubuntu:/home/ubuntu/Distributed Cyclone/CLIENT_avx2# ./Dist_Cyclone -i 0.0.0.0 -p 12345
================= SRV COMMUNICATION =================
SRV ip-address       : 0.0.0.0
SRV port             : 12345
Connection status    : Established
================= WORK IN PROGRESS ==================
Target Address: 128z5d7nN7PkCuX5qoA4Ys6pmxUYnEy86k
CPU Threads   : 8
Mkeys/s       : 8.943
Total Checked : 119586937
Elapsed Time  : 00:00:13
Progress      : 0.00 %%
Total ranges  : 6
=================== FOUND MATCH! ====================
     The key was found and sent to the server!

```

**Server side**
```bash
root@ubuntu:/home/ubuntu/Distributed Cyclone/SRV# python3 srv.py 
Database 'database.db' exists. Use it? [Y/N]: N
======= Creating Cyclone database =======
Creating new database 'database.db'
Enter range start hex: 0
Enter range end hex: 6facFFFF
Enter segments count: 10
Enter target address: 128z5d7nN7PkCuX5qoA4Ys6pmxUYnEy86k
========= Cyclone server status =========
Clients    : 0
Computed   : 6
Computing  : 0
Remain     : 4
Blocked IP : 1
Found key  : 0000000000000000000000000000000000000000000000000000000006AC3875
=========================================

```

**Server log.txt**
```bash
Log in DB!
Use sqlitebrowser for DB navigating!
Installing:
apt install sqlitebrowser
sqlitebrowser
And that's all!

```
**Server blocking.txt**
```bash
[2025-03-27 17:57:24] [!] Blocked 127.0.0.1 for 8h

```

## 🛠️ Getting Started

To get started with Cyclone, clone the repository and follow the installation instructions:

```bash
## AVX2 ##
git clone https://github.com/Dookoo2/Distributed-Cyclone.git
cd Distributed-Cyclone/Client/Dist_Cyclone_avx2/

g++ -std=c++17 -Ofast -ffast-math -funroll-loops -ftree-vectorize -fstrict-aliasing -fno-semantic-interposition -fvect-cost-model=unlimited -fno-trapping-math -fipa-ra -fipa-modref -flto -fassociative-math -fopenmp -mavx2 -mbmi2 -madx -o Dist_Cyclone Dist_Cyclone.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp
```

## ✌️**TIPS**
BTC: bc1qtq4y9l9ajeyxq05ynq09z8p52xdmk4hqky9c8n

