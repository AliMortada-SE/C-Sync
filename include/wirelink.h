#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stddef.h>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_DIGEST_LENGTH 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA_CTX;

// Inline implementations
#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define BLK0(i) (block->l[i] = (ROL(block->l[i], 24) & 0xFF00FF00) | (ROL(block->l[i], 8) & 0x00FF00FF))
#define BLK(i) (block->l[i & 15] = ROL(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

#define R0(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + BLK0(i) + 0x5A827999 + ROL(v, 5); w = ROL(w, 30);
#define R1(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + BLK(i) + 0x5A827999 + ROL(v, 5); w = ROL(w, 30);
#define R2(v, w, x, y, z, i) z += (w ^ x ^ y) + BLK(i) + 0x6ED9EBA1 + ROL(v, 5); w = ROL(w, 30);
#define R3(v, w, x, y, z, i) z += (((w | x) & y) | (w & x)) + BLK(i) + 0x8F1BBCDC + ROL(v, 5); w = ROL(w, 30);
#define R4(v, w, x, y, z, i) z += (w ^ x ^ y) + BLK(i) + 0xCA62C1D6 + ROL(v, 5); w = ROL(w, 30);

typedef union {
    uint8_t c[64];
    uint32_t l[16];
} CHAR64LONG16;

static inline void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    CHAR64LONG16 block[1];
    
    memcpy(block, buffer, 64);
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    
    R0(a,b,c,d,e,0);  R0(e,a,b,c,d,1);  R0(d,e,a,b,c,2);  R0(c,d,e,a,b,3);
    R0(b,c,d,e,a,4);  R0(a,b,c,d,e,5);  R0(e,a,b,c,d,6);  R0(d,e,a,b,c,7);
    R0(c,d,e,a,b,8);  R0(b,c,d,e,a,9);  R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static inline void SHA1_Init(SHA_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

static inline void SHA1_Update(SHA_CTX *context, const uint8_t *data, size_t len) {
    size_t i, j;
    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1_Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1_Transform(context->state, &data[i]);
        }
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

static inline void SHA1_Final(uint8_t digest[SHA_DIGEST_LENGTH], SHA_CTX *context) {
    uint8_t finalcount[8];
    for (unsigned i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    SHA1_Update(context, (uint8_t *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1_Update(context, (uint8_t *)"\0", 1);
    }
    SHA1_Update(context, finalcount, 8);
    for (unsigned i = 0; i < SHA_DIGEST_LENGTH; i++) {
        digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

static inline void SHA1(const uint8_t *data, size_t len, uint8_t digest[SHA_DIGEST_LENGTH]) {
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, data, len);
    SHA1_Final(digest, &context);
}

#ifdef __cplusplus
}
#endif

#endif // SHA_H
#ifndef WIRELINK_H
#define WIRELINK_H

#define IPv4 AF_INET
#define TCP_PROTOCOL SOCK_STREAM
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h> // Core socket functions
#include <netinet/in.h> // Address structures
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>     // For close()
#include <sys/uio.h>   // writev, readv
#include <sys/epoll.h>
#include <fcntl.h>
#endif
#include <iostream>
#include <cstdint>
#include <cstring>      
#include <string>
#include <vector>
#include <array>
#include <random>
#include <fstream>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <atomic>
#include <memory>
#include <optional>
#include <netdb.h>
#include <sys/resource.h>
#include <csignal>
//WEB SOCKET PROTOCOL
// byte 0 :
// bits 0 to 3-> opcode (0x1=text,0x2=binary,0x8=close,0x9=ping,0xA=pong)
// bits 4 to 6 (Reserved, default 0)
// bit  7 -> if 1 no incoming fragment, if 0 there are more
// 0001 -> text
// 0010 -> binary
// 1000 -> close
// 1001 -> ping
// 1010 -> pong
// byte 1:
// bits 0 to 6 -> Payload len:
// bit  7 -> Mask:if 1 than payload is masked.
// if the length 125 or less, this is the size of payload,
// if it 126, read the next 2 bytes as uint 16(these 2 bytes converted to one uint16 variable)  
// if 127, read the next 8 bytes as uint64(take these 8 bytes and put the in uint64 var)

//SOCKS5 PROTOCOL
//Phase 1(handshake/Greeting):
//Client Packet:
//byte 0: 0x05 (socks5)
//byte 1: 0x0n (how many methods client have)
//byte 2...n   (methods client have) 
//Server response:
//byte 0: 0x05
//byte 1: 0xn (what server used as method)
//methods codes:
//0x00 : no auth
//0x01 : GSSAPI
//0x02 : Username/Password
//0x03–0x7F: IANA assigned (unused in practice)
//0x80–0xFE: private methods
//0xFF: no acceptable method (reject)
//we will ignore all, will use here only 0x00 and 0x02(may upgrade later)

//Phase 2(auth):
//Client:
//byte 0: 0x01(auth sub-protocol version) "always 0x01"
//byte 1: username len (max 255)
//byte 2...N: username
//byte N+1: password len
//byte N+2...M: Password
//Server:
//byte 0: 0x01(auth sub-protocol version)
//byte 1: if 0x00 mean success (every thing else failed)

//Phase 3(connect)
//Client:
//byte 0: 0x05 (socks5)
//byte 1: CMD(0x01:connect, 0x02:BIND, 0x03:UDP), we will use connect
//byte 2: 0x00 (reserved) just keep it 0x00
//byte 3: ATYP (0x01:IPv4 -> 4 bytes, 0x03:domain -> 1 byte + N, 0x04:IPv6 ->16 bytes)
//byte 4...N: destination (depends on byte 3)
//byte N+1 & N+2: for Port
//Server:
//byte 0: 0x05  
//byte 1: status (if 0x00 success)
//byte 2: 0x00 (reserved)
//byte 3: ATYP (server)
//byte 4...N: bind address (server)
//byte N+1...N+2: bind port

//GREETING → AUTH → REQUEST → RELAY


class Wirelink{
    public:
    struct ClientMessage {
        int fd;
        std::vector<uint8_t> Data;
        std::string Username;
        std::string ip;
        std::string token;
    };
    struct ClientConnection {
        bool alive = true;
        bool shouldClose = false;
        int fd;
        std::string ip;
        uint16_t port;
        bool ws_handshake_done = false;
        std::atomic<bool> locked = false;
        bool ready = false;
        std::string Username;
        std::string Passsword;
        std::string token;
        std::vector<uint8_t> leftOver;
        struct websocket{
            void unmask(uint8_t* data, size_t len, const uint8_t* key);
            std::chrono::high_resolution_clock::time_point start;
            std::chrono::high_resolution_clock::time_point end;
            std::vector<uint8_t> Data;
            size_t written = 0;
            uint8_t MaskKey[4];
            uint8_t headerSize;
            uint8_t mode;
            uint8_t len;
            bool FIN;
            bool mask;
            size_t size;
        };
        websocket ws;
        void clear(){
            fd = 0;
            ip.clear();
            port = 0;
            ws_handshake_done = false;
            locked.store(false);
            ready = false;
            Username = "";
            Passsword = "";
            token = "";
            ws = {};
        }
    };

    static bool Initialize();    //Windows  
    static void Cleanup();      //Windows
    bool Open(uint16_t port);
    bool Accept();
    bool Close();
    bool Connect(const std::string& IP,uint16_t port);
    bool isConnected();
    bool isRunning();
    void notify(ClientMessage client);
    ClientMessage getClientInfo();
    void SetNonBlocking(int fd);
    void EventLoop();
    class Text{
        public:
        Text(Wirelink& p);
        bool Send(const std::string& message);
        std::string Receive();
        private:
        Wirelink& parent;
    };
    class WebSocket{
        public:
        WebSocket(Wirelink& p);
        bool Send_WS_Handshake();
        bool Catch_WS_Handshake();
        std::pair<std::string,std::string> Encode_WS_Handshake(sockaddr_in socketAddress);
        std::string Decode_WS_Handshake(std::string& HTTP_Request);
        bool Send(std::vector<uint8_t>* Data,int client_fd = -1);
        bool Receive(std::vector<uint8_t>* Data);
        inline void setText();
        inline void setBinary();
        void setMask();
        bool Ping();
        bool Pong(std::vector<uint8_t>* pingData);
        bool SendClose(uint16_t code);
        void KeepAlive(int seconds);    
        std::vector<uint8_t> BuildFrame(size_t size); 
        size_t DecodeFrame(std::vector<uint8_t> binary, ClientConnection& client);
        Wirelink& parent;
        struct OPCODE {
            struct CURRENT{
                uint8_t mode = 0x1;
                bool FIN = true;
            };
            CURRENT current;
            inline bool getFin(uint8_t byte0);
            inline uint8_t getOpcode(uint8_t byte0);
            inline uint8_t setFin(uint8_t byte0, bool fin);
            inline uint8_t setOpcode(uint8_t byte0, uint8_t opcode);
            static constexpr uint8_t fin    = 0x0;
            static constexpr uint8_t text   = 0x1;
            static constexpr uint8_t binary = 0x2;
            static constexpr uint8_t close  = 0x8;
            static constexpr uint8_t ping   = 0x9;
            static constexpr uint8_t pong   = 0xA;
        };
        OPCODE opcode;
        struct PAYLOAD{
            struct CURRENT{
                bool mask = false;
                uint8_t MaskKey[4];
                size_t size = 0;
                std::vector<uint8_t> frame;
            };
            CURRENT current;
            inline bool getMask(uint8_t byte1);
            inline uint8_t setMask(uint8_t byte1, bool mask);
            inline uint8_t getPayloadLen(uint8_t byte1);
            inline uint8_t setPayloadLen(uint8_t byte1, uint8_t len);
            inline uint16_t readLen16(uint8_t* buffer, size_t offset);
            inline uint64_t readLen64(uint8_t* buffer, size_t offset);
            inline void writeLen16(uint8_t* buffer, size_t offset, uint16_t len);
            inline void writeLen64(uint8_t* buffer, size_t offset, uint64_t len);
            inline void generateMaskKey(uint8_t* key);
            inline void mask(uint8_t* data, size_t len, const uint8_t* key);
            inline void unmask(uint8_t* data, size_t len, const uint8_t* key);
            inline void writeMaskKey(uint8_t* buffer, size_t offset, const uint8_t* key);
            inline void readMaskKey(const uint8_t* buffer, size_t offset, uint8_t* key);
        };
        PAYLOAD payload;
    };
    class Socks5{
        public:     
        enum State { GREETING, AUTH, REQUEST,CONNECTING, RELAY };
        Socks5(Wirelink& p);
        struct ProxyClient{
            std::string username;
            std::string ip;
            std::vector<uint8_t> pending_reply;
            State state = GREETING;
            int client_fd;
            int remote_fd = -1;
            int8_t method = 0x00;
            uint8_t ATYP  = 0x00;
            bool alive = true;

            int request_count = 0;
            FILE* client_log = nullptr;
            FILE* remote_log = nullptr;
        };
        struct Code{
            uint8_t SOCKS5    = 0x05;
            uint8_t NO_AUTH   = 0x00;
            uint8_t USER_PASS = 0x02;
        };
        struct CMD{
            uint8_t CONNECT   = 0x01;
            uint8_t BIND      = 0x02;
            uint8_t UDP       = 0X03;
        };
        struct ATYP{
            uint8_t IPV4      = 0x01;
            uint8_t DOMAIN    = 0x03;
            uint8_t IPV6      = 0x04;
        };
        Code code;
        CMD cmd;
        ATYP atyp;
        std::unordered_map<int, ProxyClient> clients;  // fd → client
        std::unordered_map<int, int> pairs;            // remote_fd → client_fd
        void Reader();
        std::optional<std::vector<uint8_t>> HttpConnect(std::vector<uint8_t>* buffer, int* fd);
        std::optional<std::vector<uint8_t>> Greeting   (std::vector<uint8_t>* buffer, int* fd);
        std::optional<std::vector<uint8_t>> Auth       (std::vector<uint8_t>* buffer, int* fd);
        std::optional<std::vector<uint8_t>> Request    (std::vector<uint8_t>* buffer, int* fd);

        Wirelink& parent;

    };
    class Proxy{
        public:
        Proxy(Wirelink& p);
        struct CLIENT{
            int fd;
            int peer = -1;
        };
        struct PEER {
            std::string ip;
            uint16_t port;
            int totalClient = 0;
        };
        bool LoadIPs(std::string filename);
        bool LoadWhitelist(std::string filename);
        std::optional<int>  ConnectToPeer(int client_fd,  int epoll_fd);
        void Forward();
        int SleepTime = 0;
        int rotationSpeed=0;
        int maxClients = 0;
        std::unordered_set<std::string> whitelist;
        std::vector<PEER> Peers;
        std::unordered_map<int,CLIENT> client;
        std::unordered_map<int, int> peer;
        std::unordered_map<std::string, sockaddr_in6> dns_cache;
        std::vector<std::string> IPv6List;
        bool LoadIPv6(std::string filename, int start, int count);
        int InitDirectConnect(const std::string& target_host, int ipv6_index);
        enum PendingState { PENDING_CONNECT, PENDING_RESPONSE };

        struct PendingConnect {
            int client_fd = -1;
            int peer_fd = -1;
            int peer_index = 0;
            std::string target_host;
            PendingState state = PENDING_CONNECT;
            std::chrono::steady_clock::time_point created_at;
        };

        std::unordered_map<int, PendingConnect> pending;       // peer_fd  → pending handshake
        std::unordered_map<int, int>            pending_client; // client_fd → peer_fd
        std::atomic<int> total_requests{0};
        std::atomic<int> total_incoming{0};
        std::atomic<int> total_rl{0};
        std::atomic<int> next_rotate{-1};
        std::deque<int>  rotate_order;
        std::mutex       rotate_mtx;
        std::vector<std::chrono::steady_clock::time_point> rl_until;
        int rl_cooldown_sec = 30;

        int round_count = 0;

        int  InitPeerConnect(int peer_index);
        void CleanupFd(int fd, int epoll_fd);
        void CleanupPair(int fd, int epoll_fd);
        bool HandleNewClient(int client_fd, int epoll_fd);
        bool HandlePeerConnected(int peer_fd, int epoll_fd);
        bool HandlePeerResponse(int peer_fd, int epoll_fd);
        Wirelink& parent;
    };
    struct Algorithms{
        std::string base64_encode(const uint8_t* data, size_t len);
        std::string FindSecKey(const std::string& request);
        std::string sha1(const std::string& data);
        std::array<uint8_t, 16> generateWSKey();
        std::string FindAcceptSecKey(const std::string& request);
        inline void setBit(uint8_t& byte, uint8_t bit, bool value);
        inline bool getBit(uint8_t byte, uint8_t bit);
        std::string generateToken(int length = 32);
    };
    
    Socks5 socks5;
    Proxy proxy;
    Text text;
    WebSocket ws;
    Algorithms alg;
    Wirelink();

    

    sockaddr_in serverAddress;
    sockaddr_in clientAddress;
    std::atomic<ClientConnection*> ClientInfo = nullptr;
    std::atomic<bool> ready = false;
    int clientSocket;

    std::unordered_map<std::string,std::string> tokenMap;
    std::unordered_map<int, std::unique_ptr<ClientConnection>> Clients;
    std::vector<ClientMessage> Queue;
    private:
    bool Connected = false;
    bool isServer = false;
    bool isClient = false;
    bool running = false;
    char buffer[1024]={0};
    int serverSocket;
    std::mutex mtx;
};
#endif     