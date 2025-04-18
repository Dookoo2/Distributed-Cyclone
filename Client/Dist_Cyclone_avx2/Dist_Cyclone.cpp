//Win: x86_64-w64-mingw32-g++ -std=c++11 -Ofast -ffast-math -funroll-loops -ftree-vectorize -fstrict-aliasing -fno-semantic-interposition -fvect-cost-model=unlimited -fno-trapping-math -fipa-ra -fipa-modref -flto -fassociative-math -fopenmp -mavx2 -mbmi2 -madx -static -static -o Dist_Cyclone.exe Dist_Cyclone.cpp -lws2_32 SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp

//Linux: g++ -std=c++17 -Ofast -ffast-math -funroll-loops -ftree-vectorize -fstrict-aliasing -fno-semantic-interposition -fvect-cost-model=unlimited -fno-trapping-math -fipa-ra -fipa-modref -flto -fassociative-math -fopenmp -mavx2 -mbmi2 -madx -o Dist_Cyclone Dist_Cyclone.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp

#include <thread>
#include <immintrin.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <chrono>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <omp.h>
#include <array>
#include <utility>
#include <cstdlib>
#include <csignal>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    #define	SIGHUP	1	/* hangup */
#else
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#include "p2pkh_decoder.h"
#include "sha256_avx2.h"
#include "ripemd160_avx2.h"
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

static constexpr int POINTS_BATCH_SIZE = 256;
static constexpr int HASH_BATCH_SIZE = 8;
static constexpr double STATUS_INTERVAL_SEC = 5.0;

static int g_sock = -1;
static std::string g_serverIp;
static int g_serverPort = 0;
static std::string g_targetAddress;
static unsigned long long g_totalRanges = 0ULL;
static std::string g_currentRange;
static bool g_globalMatchFound = false;
static bool g_searchFinished = false;
static std::string g_foundPrivHex;
static std::string g_foundPubHex;
static std::string g_foundWIF;
static unsigned long long g_globalComparedCount = 0ULL;
static double g_globalElapsedTime = 0.0;
static std::chrono::time_point<std::chrono::high_resolution_clock> g_timeStart;
static bool g_timeInitialized = false;

static std::vector<uint64_t> hexToBigNum(const std::string &hex) {
    std::vector<uint64_t> v;
    size_t l = hex.size();
    v.reserve((l + 15) / 16);
    for (size_t i = 0; i < l; i += 16) {
        size_t s = (l >= 16 + i) ? l - 16 - i : 0;
        size_t pl = (l >= 16 + i) ? 16 : (l - i);
        uint64_t val = std::stoull(hex.substr(s, pl), nullptr, 16);
        v.push_back(val);
    }
    return v;
}

static std::string bigNumToHex(const std::vector<uint64_t> &num) {
    std::ostringstream oss;
    for (auto it = num.rbegin(); it != num.rend(); ++it) {
        if (it != num.rbegin()) oss << std::setw(16) << std::setfill('0');
        oss << std::hex << std::uppercase << *it;
    }
    return oss.str();
}

static std::vector<uint64_t> singleElementVector(uint64_t val) {
    return { val };
}

static std::vector<uint64_t> bigNumAdd(const std::vector<uint64_t> &a, const std::vector<uint64_t> &b) {
    std::vector<uint64_t> sum;
    sum.reserve(std::max(a.size(), b.size()) + 1);
    uint64_t carry = 0;
    for (size_t i = 0, sz = std::max(a.size(), b.size()); i < sz; i++) {
        uint64_t x = (i < a.size()) ? a[i] : 0ULL;
        uint64_t y = (i < b.size()) ? b[i] : 0ULL;
        __uint128_t s = ( __uint128_t )x + ( __uint128_t )y + carry;
        carry = (uint64_t)(s >> 64);
        sum.push_back((uint64_t)s);
    }
    if (carry) sum.push_back(carry);
    return sum;
}

static std::vector<uint64_t> bigNumSubtract(const std::vector<uint64_t> &a, const std::vector<uint64_t> &b) {
    std::vector<uint64_t> diff = a;
    uint64_t borrow = 0;
    for (size_t i = 0; i < b.size(); i++) {
        uint64_t sub = b[i];
        if (diff[i] < sub + borrow) {
            diff[i] = diff[i] + (~0ULL) - sub - borrow + 1ULL;
            borrow = 1;
        } else {
            diff[i] -= (sub + borrow);
            borrow = 0;
        }
    }
    for (size_t i = b.size(); i < diff.size() && borrow; i++) {
        if (diff[i] == 0ULL) {
            diff[i] = ~0ULL;
        } else {
            diff[i] -= 1;
            borrow = 0;
        }
    }
    while (!diff.empty() && diff.back() == 0ULL) diff.pop_back();
    return diff;
}

static std::pair<std::vector<uint64_t>, uint64_t> bigNumDivide(const std::vector<uint64_t> &a, uint64_t d) {
    std::vector<uint64_t> q(a.size(), 0ULL);
    uint64_t r = 0;
    for (int i = (int)a.size() - 1; i >= 0; i--) {
        __uint128_t tmp = ((__uint128_t)r << 64) | a[i];
        uint64_t qq = (uint64_t)(tmp / d);
        uint64_t rr = (uint64_t)(tmp % d);
        q[i] = qq;
        r = rr;
    }
    while (!q.empty() && q.back() == 0ULL) q.pop_back();
    return {q, r};
}

static long double hexStrToLongDouble(const std::string &hex) {
    long double res = 0.0L;
    for (char c : hex) {
        res *= 16.0L;
        if (c >= '0' && c <= '9') res += (c - '0');
        else if (c >= 'A' && c <= 'F') res += (c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') res += (c - 'a' + 10);
    }
    return res;
}

static inline std::string padHexTo64(const std::string &hex) {
    if (hex.size() >= 64) return hex;
    return std::string(64 - hex.size(), '0') + hex;
}

static inline Int hexToInt(const std::string &hex) {
    Int x;
    char buf[65] = {0};
    std::strncpy(buf, hex.c_str(), 64);
    x.SetBase16(buf);
    return x;
}

static inline std::string intToHex(const Int &v) {
    Int tmp;
    tmp.Set((Int*)&v);
    return tmp.GetBase16();
}

static inline bool intGreater(const Int &a, const Int &b) {
    std::string ha = ((Int&)a).GetBase16();
    std::string hb = ((Int&)b).GetBase16();
    if (ha.size() != hb.size()) return (ha.size() > hb.size());
    return (ha > hb);
}

static inline bool isEven(const Int &n) {
    return ((Int&)n).IsEven();
}

static inline std::string intXToHex64(const Int &x) {
    Int t;
    t.Set((Int*)&x);
    std::string h = t.GetBase16();
    if (h.size() < 64) h.insert(0, 64 - h.size(), '0');
    return h;
}

static inline std::string pointToCompressedHex(const Point &p) {
    return (isEven(p.y) ? "02" : "03") + intXToHex64(p.x);
}

static inline void pointToCompressedBin(const Point &p, uint8_t out[33]) {
    out[0] = isEven(p.y) ? 0x02 : 0x03;
    Int tmp;
    tmp.Set((Int*)&p.x);
    for (int i = 0; i < 32; i++) out[1 + i] = (uint8_t)tmp.GetByte(31 - i);
}

static inline void prepareShaBlock(const uint8_t *src, size_t len, uint8_t *blk) {
    std::memset(blk, 0, 64);
    std::memcpy(blk, src, len);
    blk[len] = 0x80;
    uint32_t bits = (uint32_t)(len * 8);
    blk[60] = (uint8_t)((bits >> 24) & 0xFF);
    blk[61] = (uint8_t)((bits >> 16) & 0xFF);
    blk[62] = (uint8_t)((bits >> 8) & 0xFF);
    blk[63] = (uint8_t)(bits & 0xFF);
}

static inline void prepareRipemdBlock(const uint8_t *src, uint8_t *blk) {
    std::memset(blk, 0, 64);
    std::memcpy(blk, src, 32);
    blk[32] = 0x80;
    uint32_t bits = 256;
    blk[60] = (uint8_t)((bits >> 24) & 0xFF);
    blk[61] = (uint8_t)((bits >> 16) & 0xFF);
    blk[62] = (uint8_t)((bits >> 8) & 0xFF);
    blk[63] = (uint8_t)(bits & 0xFF);
}

static void computeHash160BatchBinSingle(int n, uint8_t pk[][33], uint8_t h[][20]) {
    std::array<std::array<uint8_t, 64>, HASH_BATCH_SIZE> shaIn;
    std::array<std::array<uint8_t, 32>, HASH_BATCH_SIZE> shaOut;
    std::array<std::array<uint8_t, 64>, HASH_BATCH_SIZE> rmdIn;
    std::array<std::array<uint8_t, 20>, HASH_BATCH_SIZE> rmdOut;
    size_t totalBatches = (n + (HASH_BATCH_SIZE - 1)) / HASH_BATCH_SIZE;
    for (size_t b = 0; b < totalBatches; b++) {
        size_t count = std::min<size_t>(HASH_BATCH_SIZE, n - b * HASH_BATCH_SIZE);
        for (size_t i = 0; i < count; i++) prepareShaBlock(pk[b * HASH_BATCH_SIZE + i], 33, shaIn[i].data());
        for (size_t i = count; i < HASH_BATCH_SIZE; i++) std::memcpy(shaIn[i].data(), shaIn[0].data(), 64);
        const uint8_t *inPtr[HASH_BATCH_SIZE];
        uint8_t *outPtr[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; i++) {
            inPtr[i] = shaIn[i].data();
            outPtr[i] = shaOut[i].data();
        }
        sha256avx2_8B(inPtr[0], inPtr[1], inPtr[2], inPtr[3], inPtr[4], inPtr[5], inPtr[6], inPtr[7],
                      outPtr[0], outPtr[1], outPtr[2], outPtr[3], outPtr[4], outPtr[5], outPtr[6], outPtr[7]);
        for (size_t i = 0; i < count; i++) prepareRipemdBlock(shaOut[i].data(), rmdIn[i].data());
        for (size_t i = count; i < HASH_BATCH_SIZE; i++) std::memcpy(rmdIn[i].data(), rmdIn[0].data(), 64);
        for (int i = 0; i < HASH_BATCH_SIZE; i++) {
            inPtr[i] = rmdIn[i].data();
            outPtr[i] = rmdOut[i].data();
        }
        ripemd160avx2::ripemd160avx2_32((unsigned char*)inPtr[0], (unsigned char*)inPtr[1],
                                        (unsigned char*)inPtr[2], (unsigned char*)inPtr[3],
                                        (unsigned char*)inPtr[4], (unsigned char*)inPtr[5],
                                        (unsigned char*)inPtr[6], (unsigned char*)inPtr[7],
                                        outPtr[0], outPtr[1], outPtr[2], outPtr[3],
                                        outPtr[4], outPtr[5], outPtr[6], outPtr[7]);
        for (size_t i = 0; i < count; i++) std::memcpy(h[b * HASH_BATCH_SIZE + i], rmdOut[i].data(), 20);
    }
}

static std::string formatElapsedTime(double sec) {
    int hrs = (int)sec / 3600;
    int mins = ((int)sec % 3600) / 60;
    int sc = (int)sec % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hrs << ":"
        << std::setw(2) << std::setfill('0') << mins << ":"
        << std::setw(2) << std::setfill('0') << sc;
    return oss.str();
}

static void printFullStats(int numCPUs, double mkeysPerSec, unsigned long long totalChecked,
                           double elapsedTime, long double progress) {
    static bool firstPrint = true;
    if (!firstPrint) std::cout << "\033[12A";
    else firstPrint = false;
    std::cout << "================= SRV COMMUNICATION =================\n";
    std::cout << "SRV ip-address       : " << g_serverIp << "\n";
    std::cout << "SRV port             : " << g_serverPort << "\n";
    std::cout << "Connection status    : Established\n";
    std::cout << "================= WORK IN PROGRESS ==================\n";
    std::cout << "Target Address: " << g_targetAddress << "\n";
    std::cout << "CPU Threads   : " << numCPUs << "\n";
    std::cout << "Mkeys/s       : " << std::fixed << std::setprecision(2) << mkeysPerSec << "\n";
    std::cout << "Total Checked : " << totalChecked << "\n";
    std::cout << "Elapsed Time  : " << formatElapsedTime(elapsedTime) << "\n";
    std::cout << "Progress      : " << std::fixed << std::setprecision(2) << progress << " %\n";
    std::cout << "Total ranges  : " << g_totalRanges << "\n";
    std::cout.flush();
    if (g_searchFinished) {
        if (g_globalMatchFound) {
            std::cout << "=================== FOUND MATCH! ====================\n";
            std::cout << "     The key was found and sent to the server!\n";
        } else {
            std::cout << "\n=================== KEY NOT FOUND ====================\n";
            std::cout << "                  The key not found!\n";
        }
    }
    std::cout.flush();
}

static void handleSignal(int) {
    if (!g_currentRange.empty() && g_sock != -1) {
        std::string msg = g_currentRange + " NOT COMPUTED\n";
        send(g_sock, msg.c_str(), msg.size(), 0);
    }
    close(g_sock);
    std::exit(0);
}

static std::string recvLine(int sock) {
    std::string line;
    char c;
    while (true) {
        ssize_t r = recv(sock, &c, 1, 0);
        if (r == 1) {
            if (c == '\n') break;
            line.push_back(c);
        } else if (r == 0) {
            return "";
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return "";
        }
    }
    return line;
}

static void aliveThreadFunc() {
    while (!g_searchFinished) {
        std::this_thread::sleep_for(std::chrono::seconds(29));
        if (!g_searchFinished && g_sock != -1) {
            std::string aliveMsg = "ALIVE\n";
            send(g_sock, aliveMsg.c_str(), aliveMsg.size(), 0);
        }
    }
}

struct ThreadRangeStruct {
    std::string startHex;
    std::string endHex;
};

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "-i") && i + 1 < argc) g_serverIp = argv[++i];
        else if (!std::strcmp(argv[i], "-p") && i + 1 < argc) g_serverPort = std::stoi(argv[++i]);
        else {
            std::cerr << "Usage: " << argv[0] << " -i <IP> -p <port>\n";
            return 1;
        }
    }
    if (g_serverIp.empty() || g_serverPort == 0) {
        std::cerr << "Usage: " << argv[0] << " -i <IP> -p <port>\n";
        return 1;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(g_serverPort);
    if (inet_pton(AF_INET, g_serverIp.c_str(), &srv.sin_addr) <= 0) {
        std::cerr << "Invalid IP address\n";
        return 1;
    }
    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect");
        return 1;
    }
    g_sock = sock;
    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);
    signal(SIGHUP, handleSignal);
    std::thread alv(aliveThreadFunc);
    alv.detach();
    {
        std::string cmd = "get target\n";
        if (send(sock, cmd.c_str(), cmd.size(), 0) < 0) {
            close(sock);
            return 1;
        }
        std::string resp = recvLine(sock);
        if (resp.empty()) {
            close(sock);
            return 1;
        }
        g_targetAddress = resp;
    }
    std::vector<uint8_t> targetHash160;
    try {
        targetHash160 = P2PKHDecoder::getHash160(g_targetAddress);
        if (targetHash160.size() != 20) throw std::invalid_argument("Bad hash160 length");
    } catch (...) {
        close(sock);
        return 1;
    }
    if (!g_timeInitialized) {
        g_timeStart = std::chrono::high_resolution_clock::now();
        g_timeInitialized = true;
    }
    int numCPUs = omp_get_num_procs();
    printFullStats(numCPUs, 0.0, g_globalComparedCount, g_globalElapsedTime, 0.0L);
    while (true) {
        std::string getCmd = "get range\n";
        if (send(sock, getCmd.c_str(), getCmd.size(), 0) < 0) {
            g_searchFinished = true;
            break;
        }
        std::string rangeStr = recvLine(sock);
        if (rangeStr.empty()) {
            g_searchFinished = true;
            break;
        }
        if (rangeStr == "NO RANGE") {
            g_searchFinished = true;
            break;
        }
        g_currentRange = rangeStr;
        g_totalRanges++;
        size_t cPos = rangeStr.find(':');
        if (cPos == std::string::npos) {
            g_searchFinished = true;
            break;
        }
        std::string rangeStartHex = rangeStr.substr(0, cPos);
        std::string rangeEndHex = rangeStr.substr(cPos + 1);
        auto rangeStart = hexToBigNum(rangeStartHex);
        auto rangeEnd = hexToBigNum(rangeEndHex);
        bool valid = true;
        if (rangeStart.size() > rangeEnd.size() ||
           (rangeStart.size() == rangeEnd.size() && bigNumToHex(rangeStart) > bigNumToHex(rangeEnd))) {
            valid = false;
        }
        if (!valid) {
            g_searchFinished = true;
            break;
        }
        auto rSize = bigNumSubtract(rangeEnd, rangeStart);
        rSize = bigNumAdd(rSize, singleElementVector(1ULL));
        std::string rSizeHex = bigNumToHex(rSize);
        long double totalRangeLD = hexStrToLongDouble(rSizeHex);
        unsigned long long rangeComparedCount = 0ULL;
        auto divres = bigNumDivide(rSize, (uint64_t)numCPUs);
        auto chunkSize = divres.first;
        uint64_t remainder = divres.second;
        std::vector<ThreadRangeStruct> thrRanges(numCPUs);
        std::vector<uint64_t> curStart = rangeStart;
        for (int t = 0; t < numCPUs; t++) {
            auto curEnd = bigNumAdd(curStart, chunkSize);
            if (t < (int)remainder) curEnd = bigNumAdd(curEnd, singleElementVector(1ULL));
            curEnd = bigNumSubtract(curEnd, singleElementVector(1ULL));
            thrRanges[t].startHex = bigNumToHex(curStart);
            thrRanges[t].endHex = bigNumToHex(curEnd);
            curStart = bigNumAdd(curEnd, singleElementVector(1ULL));
        }
        bool matchFound = false;
        auto lastUpdate = std::chrono::high_resolution_clock::now();
        #pragma omp parallel num_threads(numCPUs) shared(matchFound, totalRangeLD, targetHash160, lastUpdate, rangeComparedCount)
        {
            int tid = omp_get_thread_num();
            Int privKey = hexToInt(thrRanges[tid].startHex);
            Int endKey = hexToInt(thrRanges[tid].endHex);
            Secp256K1 secp;
            secp.Init();
            std::vector<Point> plusPoints(POINTS_BATCH_SIZE);
            std::vector<Point> minusPoints(POINTS_BATCH_SIZE);
            for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                Int tmp; tmp.SetInt32(i);
                Point p = secp.ComputePublicKey(&tmp);
                plusPoints[i] = p;
                p.y.ModNeg();
                minusPoints[i] = p;
            }
            std::vector<Int> deltaX(POINTS_BATCH_SIZE);
            IntGroup ig(POINTS_BATCH_SIZE);
            int fbSize = 2 * POINTS_BATCH_SIZE;
            std::vector<Point> pBatch(fbSize);
            uint8_t pubKeys[fbSize][33];
            uint8_t hashes[HASH_BATCH_SIZE][20];
            int bCount = 0;
            int idxMap[HASH_BATCH_SIZE];
            unsigned long long locCount = 0ULL;
            __m128i tgt = _mm_loadu_si128(reinterpret_cast<const __m128i*>(targetHash160.data()));
            while (true) {
                if (matchFound) break;
                if (intGreater(privKey, endKey)) break;
                Int startPk; startPk.Set(&privKey);
                Point startP = secp.ComputePublicKey(&startPk);
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    deltaX[i].ModSub(&plusPoints[i].x, &startP.x);
                }
                ig.Set(deltaX.data());
                ig.ModInv();
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    Point tp = startP;
                    Int dY; dY.ModSub(&plusPoints[i].y, &startP.y);
                    Int slope; slope.ModMulK1(&dY, &deltaX[i]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);
                    Int nx; nx.Set(&startP.x);
                    nx.ModNeg(); nx.ModAdd(&slopeSq); nx.ModSub(&plusPoints[i].x);
                    tp.x.Set(&nx);
                    Int dx; dx.Set(&startP.x);
                    dx.ModSub(&tp.x); dx.ModMulK1(&slope);
                    tp.y.ModNeg(); tp.y.ModAdd(&dx);
                    pBatch[i] = tp;
                }
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    Point tp = startP;
                    Int dY; dY.ModSub(&minusPoints[i].y, &startP.y);
                    Int slope; slope.ModMulK1(&dY, &deltaX[i]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);
                    Int nx; nx.Set(&startP.x);
                    nx.ModNeg(); nx.ModAdd(&slopeSq); nx.ModSub(&minusPoints[i].x);
                    tp.x.Set(&nx);
                    Int dx; dx.Set(&startP.x);
                    dx.ModSub(&tp.x); dx.ModMulK1(&slope);
                    tp.y.ModNeg(); tp.y.ModAdd(&dx);
                    pBatch[POINTS_BATCH_SIZE + i] = tp;
                }
                for (int i = 0; i < fbSize; i++) {
                    pointToCompressedBin(pBatch[i], pubKeys[bCount]);
                    idxMap[bCount] = i;
                    bCount++;
                    if (bCount == HASH_BATCH_SIZE) {
                        computeHash160BatchBinSingle(bCount, pubKeys, hashes);
                        for (int j = 0; j < bCount; j++) {
                            __m128i c16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(hashes[j]));
                            __m128i cmp = _mm_cmpeq_epi8(c16, tgt);
                            if (_mm_movemask_epi8(cmp) == 0xFFFF) {
                                #pragma omp critical
                                {
                                    if (!matchFound && std::memcmp(hashes[j], targetHash160.data(), 20) == 0) {
                                        matchFound = true;
                                        auto tEnd = std::chrono::high_resolution_clock::now();
                                        double dt = std::chrono::duration<double>(tEnd - g_timeStart).count();
                                        g_globalElapsedTime = dt;
                                        g_globalComparedCount += locCount;
                                        rangeComparedCount += locCount;
                                        Int mk; mk.Set(&startPk);
                                        int idx = idxMap[j];
                                        if (idx < 256) {
                                            Int ofs; ofs.SetInt32(idx);
                                            mk.Add(&ofs);
                                        } else {
                                            Int ofs; ofs.SetInt32(idx - 256);
                                            mk.Sub(&ofs);
                                        }
                                        g_foundPrivHex = padHexTo64(intToHex(mk));
                                        Point matchedP = pBatch[idx];
                                        g_foundPubHex = pointToCompressedHex(matchedP);
                                        g_foundWIF = P2PKHDecoder::compute_wif(g_foundPrivHex, true);
                                    }
                                }
                            }
                            locCount++;
                            if (matchFound) break;
                        }
                        bCount = 0;
                        if (matchFound) break;
                    }
                }
                {
                    Int stp; stp.SetInt32(fbSize - 2);
                    privKey.Add(&stp);
                }
                locCount++;
                auto now = std::chrono::high_resolution_clock::now();
                double secSince = std::chrono::duration<double>(now - lastUpdate).count();
                if (secSince >= STATUS_INTERVAL_SEC) {
                    #pragma omp critical
                    {
                        g_globalComparedCount += locCount;
                        rangeComparedCount += locCount;
                        locCount = 0ULL;
                        double dt = std::chrono::duration<double>(now - g_timeStart).count();
                        g_globalElapsedTime = dt;
                        double ms = (double)g_globalComparedCount / dt / 1e6;
                        long double rg = 0.0L;
                        if (totalRangeLD > 0.0L) rg = ((long double)rangeComparedCount / totalRangeLD) * 100.0L;
                        printFullStats(numCPUs, ms, g_globalComparedCount, g_globalElapsedTime, rg);
                        lastUpdate = now;
                    }
                }
            }
            #pragma omp atomic
            g_globalComparedCount += 0;
        }
        if (matchFound) {
            std::ostringstream oss;
            oss << rangeStr << " FOUND " << g_foundPrivHex << "\n";
            std::string fMsg = oss.str();
            send(sock, fMsg.c_str(), fMsg.size(), 0);
            g_globalMatchFound = true;
            g_searchFinished = true;
            break;
        } else {
            std::string nfMsg = rangeStr + " NOT FOUND\n";
            send(sock, nfMsg.c_str(), nfMsg.size(), 0);
        }
    }
    g_searchFinished = true;
    double dtFin = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - g_timeStart).count();
    double msFin = (double)g_globalComparedCount / dtFin / 1e6;
    printFullStats(numCPUs, msFin, g_globalComparedCount, dtFin, 0.0L);

#ifdef _WIN32
    WSACleanup();
    closesocket(sock);
    #else
    close(sock);
#endif

    return 0;
}
