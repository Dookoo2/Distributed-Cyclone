// g++ -std=c++17 -Ofast -ffast-math -funroll-loops -ftree-vectorize -fstrict-aliasing -fno-semantic-interposition -fvect-cost-model=unlimited -fno-trapping-math -fipa-ra -fipa-modref -flto -fassociative-math -fopenmp -mavx2 -mbmi2 -madx -o Dist_Cyclone Dist_Cyclone.cpp SECP256K1.cpp Int.cpp IntGroup.cpp IntMod.cpp Point.cpp ripemd160_avx2.cpp p2pkh_decoder.cpp sha256_avx2.cpp

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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "p2pkh_decoder.h"
#include "sha256_avx2.h"
#include "ripemd160_avx2.h"
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

static constexpr int POINTS_BATCH_SIZE = 256;
static constexpr int HASH_BATCH_SIZE   = 8;
static constexpr double statusIntervalSec = 5.0;

int g_sock = -1;
std::string g_serverIp;
int g_serverPort = 0;
std::string g_targetAddress;
unsigned long long g_totalRanges = 0ULL;
std::string g_currentRange = "";
bool g_globalMatchFound = false;
bool g_searchFinished = false;
std::string g_foundPrivHex;
std::string g_foundPubHex;
std::string g_foundWIF;

unsigned long long g_globalComparedCount = 0ULL;
double g_globalElapsedTime = 0.0;
std::chrono::time_point<std::chrono::high_resolution_clock> g_timeStart;
bool g_timeInitialized = false;

// ---------- BigNum helpers ----------
std::vector<uint64_t> hexToBigNum(const std::string& hex) {
    std::vector<uint64_t> bigNum;
    size_t len = hex.size();
    bigNum.reserve((len + 15) / 16);
    for (size_t i = 0; i < len; i += 16) {
        size_t start = (len >= 16 + i) ? len - 16 - i : 0;
        size_t partLen = (len >= 16 + i) ? 16 : (len - i);
        uint64_t value = std::stoull(hex.substr(start, partLen), nullptr, 16);
        bigNum.push_back(value);
    }
    return bigNum;
}

std::string bigNumToHex(const std::vector<uint64_t>& num) {
    std::ostringstream oss;
    for (auto it = num.rbegin(); it != num.rend(); ++it) {
        if (it != num.rbegin()) oss << std::setw(16) << std::setfill('0');
        oss << std::hex << std::uppercase << *it;
    }
    return oss.str();
}

std::vector<uint64_t> singleElementVector(uint64_t val) {
    return { val };
}

std::vector<uint64_t> bigNumAdd(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    std::vector<uint64_t> sum;
    sum.reserve(std::max(a.size(), b.size()) + 1);
    uint64_t carry = 0;
    for (size_t i = 0, sz = std::max(a.size(), b.size()); i < sz; ++i) {
        uint64_t x = (i < a.size()) ? a[i] : 0ULL;
        uint64_t y = (i < b.size()) ? b[i] : 0ULL;
        __uint128_t s = ( __uint128_t )x + ( __uint128_t )y + carry;
        carry = (uint64_t)(s >> 64);
        sum.push_back((uint64_t)s);
    }
    if (carry) sum.push_back(carry);
    return sum;
}

std::vector<uint64_t> bigNumSubtract(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    std::vector<uint64_t> diff = a;
    uint64_t borrow = 0;
    for (size_t i = 0; i < b.size(); ++i) {
        uint64_t subtrahend = b[i];
        if (diff[i] < subtrahend + borrow) {
            diff[i] = diff[i] + (~0ULL) - subtrahend - borrow + 1ULL;
            borrow = 1;
        } else {
            diff[i] -= (subtrahend + borrow);
            borrow = 0;
        }
    }
    for (size_t i = b.size(); i < diff.size() && borrow; ++i) {
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

std::pair<std::vector<uint64_t>, uint64_t> bigNumDivide(const std::vector<uint64_t>& a, uint64_t divisor) {
    std::vector<uint64_t> quotient(a.size(), 0ULL);
    uint64_t remainder = 0;
    for (int i = (int)a.size() - 1; i >= 0; --i) {
        __uint128_t temp = ((__uint128_t)remainder << 64) | a[i];
        uint64_t q = (uint64_t)(temp / divisor);
        uint64_t r = (uint64_t)(temp % divisor);
        quotient[i] = q;
        remainder = r;
    }
    while (!quotient.empty() && quotient.back() == 0ULL) quotient.pop_back();
    return { quotient, remainder };
}

long double hexStrToLongDouble(const std::string &hex) {
    long double result = 0.0L;
    for (char c : hex) {
        result *= 16.0L;
        if (c >= '0' && c <= '9') {
            result += (c - '0');
        } else if (c >= 'A' && c <= 'F') {
            result += (c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
            result += (c - 'a' + 10);
        }
    }
    return result;
}

// ---------- Conversion to/from Int library ----------
static inline std::string padHexTo64(const std::string &hex) {
    return (hex.size() >= 64) ? hex : std::string(64 - hex.size(), '0') + hex;
}

static inline Int hexToInt(const std::string &hex) {
    Int number;
    char buf[65] = {0};
    std::strncpy(buf, hex.c_str(), 64);
    number.SetBase16(buf);
    return number;
}

static inline std::string intToHex(const Int &value) {
    Int temp;
    temp.Set((Int*)&value);
    return temp.GetBase16();
}

static inline bool intGreater(const Int &a, const Int &b) {
    std::string ha = ((Int&)a).GetBase16();
    std::string hb = ((Int&)b).GetBase16();
    if (ha.size() != hb.size()) return (ha.size() > hb.size());
    return (ha > hb);
}

// ---------- SECP helpers ----------
static inline bool isEven(const Int &number) {
    return ((Int&)number).IsEven();
}

static inline std::string intXToHex64(const Int &x) {
    Int temp;
    temp.Set((Int*)&x);
    std::string hex = temp.GetBase16();
    if (hex.size() < 64) hex.insert(0, 64 - hex.size(), '0');
    return hex;
}

static inline std::string pointToCompressedHex(const Point &point) {
    return (isEven(point.y) ? "02" : "03") + intXToHex64(point.x);
}

static inline void pointToCompressedBin(const Point &point, uint8_t outCompressed[33]) {
    outCompressed[0] = isEven(point.y) ? 0x02 : 0x03;
    Int temp;
    temp.Set((Int*)&point.x);
    for (int i = 0; i < 32; i++) {
        outCompressed[1 + i] = (uint8_t)temp.GetByte(31 - i);
    }
}

// ---------- Hash helpers ----------
inline void prepareShaBlock(const uint8_t* dataSrc, size_t dataLen, uint8_t* outBlock) {
    std::fill_n(outBlock, 64, 0);
    std::memcpy(outBlock, dataSrc, dataLen);
    outBlock[dataLen] = 0x80;
    uint32_t bitLen = (uint32_t)(dataLen * 8);
    outBlock[60] = (uint8_t)((bitLen >> 24) & 0xFF);
    outBlock[61] = (uint8_t)((bitLen >> 16) & 0xFF);
    outBlock[62] = (uint8_t)((bitLen >> 8) & 0xFF);
    outBlock[63] = (uint8_t)(bitLen & 0xFF);
}

inline void prepareRipemdBlock(const uint8_t* dataSrc, uint8_t* outBlock) {
    std::fill_n(outBlock, 64, 0);
    std::memcpy(outBlock, dataSrc, 32);
    outBlock[32] = 0x80;
    uint32_t bitLen = 256;
    outBlock[60] = (uint8_t)((bitLen >> 24) & 0xFF);
    outBlock[61] = (uint8_t)((bitLen >> 16) & 0xFF);
    outBlock[62] = (uint8_t)((bitLen >> 8) & 0xFF);
    outBlock[63] = (uint8_t)(bitLen & 0xFF);
}

static void computeHash160BatchBinSingle(int numKeys, uint8_t pubKeys[][33], uint8_t hashResults[][20]) {
    // Batches of 8
    std::array<std::array<uint8_t, 64>, HASH_BATCH_SIZE> shaInputs;
    std::array<std::array<uint8_t, 32>, HASH_BATCH_SIZE> shaOutputs;
    std::array<std::array<uint8_t, 64>, HASH_BATCH_SIZE> ripemdInputs;
    std::array<std::array<uint8_t, 20>, HASH_BATCH_SIZE> ripemdOutputs;
    size_t totalBatches = (numKeys + (HASH_BATCH_SIZE - 1)) / HASH_BATCH_SIZE;

    for (size_t batch = 0; batch < totalBatches; batch++) {
        size_t batchCount = std::min<size_t>(HASH_BATCH_SIZE, numKeys - batch * HASH_BATCH_SIZE);
        // Prepare for SHA
        for (size_t i = 0; i < batchCount; i++) {
            size_t idx = batch * HASH_BATCH_SIZE + i;
            prepareShaBlock(pubKeys[idx], 33, shaInputs[i].data());
        }
        // If fewer than HASH_BATCH_SIZE, replicate data to fill
        for (size_t i = batchCount; i < HASH_BATCH_SIZE; i++) {
            std::memcpy(shaInputs[i].data(), shaInputs[0].data(), 64);
        }
        // Perform parallel SHA
        const uint8_t* inPtr[HASH_BATCH_SIZE];
        uint8_t* outPtr[HASH_BATCH_SIZE];
        for (int i = 0; i < HASH_BATCH_SIZE; i++) {
            inPtr[i] = shaInputs[i].data();
            outPtr[i] = shaOutputs[i].data();
        }
        sha256avx2_8B(
            inPtr[0], inPtr[1], inPtr[2], inPtr[3],
            inPtr[4], inPtr[5], inPtr[6], inPtr[7],
            outPtr[0], outPtr[1], outPtr[2], outPtr[3],
            outPtr[4], outPtr[5], outPtr[6], outPtr[7]
        );

        // Prepare for RIPEMD
        for (size_t i = 0; i < batchCount; i++) {
            prepareRipemdBlock(shaOutputs[i].data(), ripemdInputs[i].data());
        }
        for (size_t i = batchCount; i < HASH_BATCH_SIZE; i++) {
            std::memcpy(ripemdInputs[i].data(), ripemdInputs[0].data(), 64);
        }
        for (int i = 0; i < HASH_BATCH_SIZE; i++) {
            inPtr[i] = ripemdInputs[i].data();
            outPtr[i] = ripemdOutputs[i].data();
        }
        ripemd160avx2::ripemd160avx2_32(
            (unsigned char*)inPtr[0], (unsigned char*)inPtr[1],
            (unsigned char*)inPtr[2], (unsigned char*)inPtr[3],
            (unsigned char*)inPtr[4], (unsigned char*)inPtr[5],
            (unsigned char*)inPtr[6], (unsigned char*)inPtr[7],
            outPtr[0], outPtr[1], outPtr[2], outPtr[3],
            outPtr[4], outPtr[5], outPtr[6], outPtr[7]
        );
        // Copy results
        for (size_t i = 0; i < batchCount; i++) {
            size_t idx = batch * HASH_BATCH_SIZE + i;
            std::memcpy(hashResults[idx], ripemdOutputs[i].data(), 20);
        }
    }
}

// ---------- Print helpers ----------
static void printUsage(const char* programName) {
    std::cerr << "Usage: " << programName << " -i <IP address> -p <port>\n";
}

static std::string formatElapsedTime(double seconds) {
    int hrs = (int)seconds / 3600;
    int mins = ((int)seconds % 3600) / 60;
    int secs = (int)seconds % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hrs << ":"
        << std::setw(2) << std::setfill('0') << mins << ":"
        << std::setw(2) << std::setfill('0') << secs;
    return oss.str();
}

static void printFullStats(int numCPUs, double mkeysPerSec, unsigned long long totalChecked,
                           double elapsedTime, long double progressPercent) {
    static bool firstPrint = true;
    if (!firstPrint) {
        // Move cursor up 12 lines to overwrite
        std::cout << "\033[12A";
    } else {
        firstPrint = false;
    }
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
    std::cout << "Progress      : " << std::fixed << std::setprecision(2) << progressPercent << " %\n";
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

// ---------- Signal handling ----------
void handleSignal(int signum) {
    if (!g_currentRange.empty() && g_sock != -1) {
        std::string msg = g_currentRange + " NOT COMPUTED\n";
        send(g_sock, msg.c_str(), msg.size(), 0);
    }
    close(g_sock);
    std::exit(0);
}

void handleAlive() {
    while (!g_searchFinished) {
        std::this_thread::sleep_for(std::chrono::seconds(300));
        if (!g_searchFinished && g_sock != -1) {
            std::string aliveMsg = "ALIVE\n";
            if (send(g_sock, aliveMsg.c_str(), aliveMsg.size(), 0) == -1) {
                std::cerr << "Error sending ALIVE to server!\n";
            }
        }
    }
}

struct ThreadRangeStruct {
    std::string startHex;
    std::string endHex;
};

int main(int argc, char* argv[]) {
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "-i") && i + 1 < argc) {
            g_serverIp = argv[++i];
        } else if (!std::strcmp(argv[i], "-p") && i + 1 < argc) {
            g_serverPort = std::stoi(argv[++i]);
        } else {
            std::cerr << "Unknown parameter: " << argv[i] << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    if (g_serverIp.empty() || g_serverPort == 0) {
        std::cerr << "Options -i <IP address> and -p <port> are required!\n";
        printUsage(argv[0]);
        return 1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return 1;
    }

    // Connect
    sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(g_serverPort);
    if (inet_pton(AF_INET, g_serverIp.c_str(), &servAddr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address: " << g_serverIp << std::endl;
        return 1;
    }
    if (connect(sock, (sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("Failed to connect to server");
        return 1;
    }
    g_sock = sock;

    // Handle signals
    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);
    signal(SIGHUP, handleSignal);

    // Launch ALIVE thread (detach to avoid join issues)
    std::thread aliveThread(handleAlive);
    aliveThread.detach();

    // Request target address
    {
        std::string cmd = "get target\n";
        if (send(sock, cmd.c_str(), cmd.size(), 0) < 0) {
            std::cerr << "Error sending 'get target' command\n";
            close(sock);
            return 1;
        }
        char buffer[256];
        ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) {
            std::cerr << "Error receiving response from server (get target).\n";
            close(sock);
            return 1;
        }
        buffer[len] = '\0';
        g_targetAddress = buffer;
        if (!g_targetAddress.empty() && g_targetAddress.back() == '\n') {
            g_targetAddress.pop_back();
        }
    }

    // Decode target address
    std::vector<uint8_t> targetHash160;
    try {
        targetHash160 = P2PKHDecoder::getHash160(g_targetAddress);
        if (targetHash160.size() != 20) {
            throw std::invalid_argument("Invalid hash160 length.");
        }
    } catch (const std::exception &ex) {
        std::cerr << "Error processing address: " << ex.what() << std::endl;
        close(sock);
        return 1;
    }

    // Timing
    if (!g_timeInitialized) {
        g_timeStart = std::chrono::high_resolution_clock::now();
        g_timeInitialized = true;
    }

    int numCPUs = omp_get_num_procs();
    printFullStats(numCPUs, 0.0, g_globalComparedCount, g_globalElapsedTime, 0.0L);

    // Main loop
    while (true) {
        // Request range
        std::string rangeCmd = "get range\n";
        if (send(sock, rangeCmd.c_str(), rangeCmd.size(), 0) < 0) {
            std::cerr << "Error sending 'get range' command\n";
            break;
        }
        char rangeBuf[256];
        ssize_t rlen = recv(sock, rangeBuf, sizeof(rangeBuf) - 1, 0);
        if (rlen <= 0) {
            // No more data or server closed
            g_searchFinished = true;
            break;
        }
        rangeBuf[rlen] = '\0';
        std::string rangeStr = rangeBuf;
        if (!rangeStr.empty() && rangeStr.back() == '\n') {
            rangeStr.pop_back();
        }
        // Could be "NO RANGE" if there's nothing left
        if (rangeStr == "NO RANGE") {
            g_searchFinished = true;
            break;
        }

        g_currentRange = rangeStr;
        g_totalRanges++;
        size_t colonPos = rangeStr.find(':');
        if (colonPos == std::string::npos) {
            // Invalid range
            g_searchFinished = true;
            break;
        }

        std::string rangeStartHex = rangeStr.substr(0, colonPos);
        std::string rangeEndHex = rangeStr.substr(colonPos + 1);

        auto rangeStart = hexToBigNum(rangeStartHex);
        auto rangeEnd = hexToBigNum(rangeEndHex);
        bool validRange = true;
        if (rangeStart.size() > rangeEnd.size() ||
           (rangeStart.size() == rangeEnd.size() &&
            bigNumToHex(rangeStart) > bigNumToHex(rangeEnd))) {
            validRange = false;
        }
        if (!validRange) {
            g_searchFinished = true;
            break;
        }

        auto rangeSize = bigNumSubtract(rangeEnd, rangeStart);
        rangeSize = bigNumAdd(rangeSize, singleElementVector(1ULL));
        std::string rangeSizeHex = bigNumToHex(rangeSize);
        long double totalRangeLD = hexStrToLongDouble(rangeSizeHex);

        unsigned long long rangeComparedCount = 0ULL;
        auto divres = bigNumDivide(rangeSize, (uint64_t)numCPUs);
        auto chunkSize = divres.first;
        uint64_t remainder = divres.second;

        std::vector<ThreadRangeStruct> threadRanges(numCPUs);
        std::vector<uint64_t> currentStart = rangeStart;
        for (int t = 0; t < numCPUs; t++) {
            auto currentEnd = bigNumAdd(currentStart, chunkSize);
            if (t < (int)remainder) {
                currentEnd = bigNumAdd(currentEnd, singleElementVector(1ULL));
            }
            currentEnd = bigNumSubtract(currentEnd, singleElementVector(1ULL));
            threadRanges[t].startHex = bigNumToHex(currentStart);
            threadRanges[t].endHex   = bigNumToHex(currentEnd);
            currentStart = bigNumAdd(currentEnd, singleElementVector(1ULL));
        }

        bool matchFound = false; // local for this range
        auto lastStatusUpdate = std::chrono::high_resolution_clock::now();

        // Parallel search
        #pragma omp parallel num_threads(numCPUs) shared(matchFound, totalRangeLD, targetHash160, lastStatusUpdate, rangeComparedCount)
        {
            int threadId = omp_get_thread_num();
            Int privateKey = hexToInt(threadRanges[threadId].startHex);
            Int threadRangeEnd = hexToInt(threadRanges[threadId].endHex);

            Secp256K1 secp;
            secp.Init();

            // Precompute plus/minus for each offset in a batch
            std::vector<Point> plusPoints(POINTS_BATCH_SIZE);
            std::vector<Point> minusPoints(POINTS_BATCH_SIZE);
            for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                Int tmp; 
                tmp.SetInt32(i);
                Point p = secp.ComputePublicKey(&tmp);
                plusPoints[i] = p;
                p.y.ModNeg();
                minusPoints[i] = p;
            }

            // We'll do 2*POINTS_BATCH_SIZE points for each step
            std::vector<Int> deltaX(POINTS_BATCH_SIZE);
            IntGroup modGroup(POINTS_BATCH_SIZE);
            int fullBatchSize = 2 * POINTS_BATCH_SIZE;

            std::vector<Point> pointBatch(fullBatchSize);
            uint8_t localPubKeys[fullBatchSize][33];
            uint8_t localHashResults[HASH_BATCH_SIZE][20];
            int localBatchCount = 0;
            int pointIndices[HASH_BATCH_SIZE];
            unsigned long long localComparedCount = 0ULL;

            __m128i target16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(targetHash160.data()));

            while (true) {
                // If we've found a match in another thread, or out of range -> break
                if (matchFound) break;
                if (intGreater(privateKey, threadRangeEnd)) break;

                // Compute public key for the "startPoint" of this iteration
                Int currentBatchKey; 
                currentBatchKey.Set(&privateKey);
                Point startPoint = secp.ComputePublicKey(&currentBatchKey);

                // Prepare deltaX for plusPoints
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    deltaX[i].ModSub(&plusPoints[i].x, &startPoint.x);
                }
                modGroup.Set(deltaX.data());
                modGroup.ModInv();

                // Compute the batch of public keys
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    // Add the offset i
                    Point tempPoint = startPoint;
                    Int deltaY; deltaY.ModSub(&plusPoints[i].y, &startPoint.y);
                    Int slope; slope.ModMulK1(&deltaY, &deltaX[i]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);

                    Int tmpX; tmpX.Set(&startPoint.x);
                    tmpX.ModNeg(); 
                    tmpX.ModAdd(&slopeSq);
                    tmpX.ModSub(&plusPoints[i].x);

                    tempPoint.x.Set(&tmpX);
                    Int diffX; diffX.Set(&startPoint.x);
                    diffX.ModSub(&tempPoint.x);
                    diffX.ModMulK1(&slope);
                    tempPoint.y.ModNeg();
                    tempPoint.y.ModAdd(&diffX);
                    pointBatch[i] = tempPoint;
                }

                // minusPoints (neg offsets)
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    Point tempPoint = startPoint;
                    Int deltaY; deltaY.ModSub(&minusPoints[i].y, &startPoint.y);
                    Int slope; slope.ModMulK1(&deltaY, &deltaX[i]);
                    Int slopeSq; slopeSq.ModSquareK1(&slope);

                    Int tmpX; tmpX.Set(&startPoint.x);
                    tmpX.ModNeg();
                    tmpX.ModAdd(&slopeSq);
                    tmpX.ModSub(&minusPoints[i].x);

                    tempPoint.x.Set(&tmpX);
                    Int diffX; diffX.Set(&startPoint.x);
                    diffX.ModSub(&tempPoint.x);
                    diffX.ModMulK1(&slope);
                    tempPoint.y.ModNeg();
                    tempPoint.y.ModAdd(&diffX);
                    pointBatch[POINTS_BATCH_SIZE + i] = tempPoint;
                }

                // Compute Hash160 on the resulting fullBatchSize points
                for (int i = 0; i < fullBatchSize; i++) {
                    pointToCompressedBin(pointBatch[i], localPubKeys[localBatchCount]);
                    pointIndices[localBatchCount] = i;
                    localBatchCount++;
                    if (localBatchCount == HASH_BATCH_SIZE) {
                        computeHash160BatchBinSingle(localBatchCount, localPubKeys, localHashResults);

                        // Compare each hash to target
                        for (int j = 0; j < HASH_BATCH_SIZE; j++) {
                            __m128i cand16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(localHashResults[j]));
                            __m128i cmp = _mm_cmpeq_epi8(cand16, target16);
                            if (_mm_movemask_epi8(cmp) == 0xFFFF) {
                                #pragma omp critical
                                {
                                    if (!matchFound &&
                                        std::memcmp(localHashResults[j], targetHash160.data(), 20) == 0) 
                                    {
                                        matchFound = true;
                                        // Save final info
                                        auto tEndTime = std::chrono::high_resolution_clock::now();
                                        double dt = std::chrono::duration<double>(tEndTime - g_timeStart).count();
                                        g_globalElapsedTime = dt;
                                        g_globalComparedCount += localComparedCount;
                                        rangeComparedCount += localComparedCount;

                                        Int matchingPrivateKey; 
                                        matchingPrivateKey.Set(&currentBatchKey);

                                        int idx = pointIndices[j];
                                        if (idx < 256) {
                                            Int offset; offset.SetInt32(idx);
                                            matchingPrivateKey.Add(&offset);
                                        } else {
                                            Int offset; offset.SetInt32(idx - 256);
                                            matchingPrivateKey.Sub(&offset);
                                        }

                                        g_foundPrivHex = padHexTo64(intToHex(matchingPrivateKey));
                                        Point matchedPoint = pointBatch[idx];
                                        g_foundPubHex  = pointToCompressedHex(matchedPoint);
                                        g_foundWIF     = P2PKHDecoder::compute_wif(g_foundPrivHex, true);
                                    }
                                }
                            }
                            localComparedCount++;
                            if (matchFound) break;
                        }
                        localBatchCount = 0;
                        if (matchFound) break;
                    }
                }

                // Move privateKey for the next iteration
                {
                    Int step; step.SetInt32(fullBatchSize - 2);
                    privateKey.Add(&step);
                }
                localComparedCount++;

                // Periodic progress
                auto now = std::chrono::high_resolution_clock::now();
                double secondsSince = std::chrono::duration<double>(now - lastStatusUpdate).count();
                if (secondsSince >= statusIntervalSec) {
                    #pragma omp critical
                    {
                        g_globalComparedCount += localComparedCount;
                        rangeComparedCount += localComparedCount;
                        localComparedCount = 0ULL;
                        double dt = std::chrono::duration<double>(now - g_timeStart).count();
                        g_globalElapsedTime = dt;

                        double ms = (double)g_globalComparedCount / dt / 1e6;
                        long double rangeProgress = 0.0L;
                        if (totalRangeLD > 0.0L) {
                            rangeProgress = ((long double)rangeComparedCount / totalRangeLD) * 100.0L;
                        }
                        printFullStats(numCPUs, ms, g_globalComparedCount, g_globalElapsedTime, rangeProgress);
                        lastStatusUpdate = now;
                    }
                }
            } // end while

            // Update global counters
            #pragma omp atomic
            g_globalComparedCount += 0;
        } // end #pragma omp parallel

        // If found in parallel region, send FOUND
        if (matchFound) {
            std::ostringstream oss;
            oss << rangeStr << " FOUND " << g_foundPrivHex << "\n";
            std::string foundMsg = oss.str();
            send(sock, foundMsg.c_str(), foundMsg.size(), 0);
            g_globalMatchFound = true;
            g_searchFinished = true;
            break;
        } else {
            // Otherwise, send NOT FOUND
            std::string notFoundMsg = rangeStr + " NOT FOUND\n";
            send(sock, notFoundMsg.c_str(), notFoundMsg.size(), 0);
        }
    } // end while(true)

    g_searchFinished = true;
    double dtFinal = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - g_timeStart).count();
    double msFinal  = (double)g_globalComparedCount / dtFinal / 1e6;
    printFullStats(numCPUs, msFinal, g_globalComparedCount, dtFinal, 0.0L);

    close(sock);
    return 0;
}
