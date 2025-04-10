#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

atomic<int> open_ports(0);  // Track open ports concurrently

// ANSI escape codes for colored output
#define RESET       "\033[0m"
#define GREEN       "\033[32m"
#define RED         "\033[31m"
#define YELLOW      "\033[33m"
#define CYAN        "\033[36m"

// Function to perform port scan using connect() for basic detection
bool scan_port(const string& ip, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    InetPton(AF_INET, ip.c_str(), &target_addr.sin_addr);

    DWORD timeout = timeout_ms;  // Timeout in milliseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    bool is_open = connect(sock, (SOCKADDR*)&target_addr, sizeof(target_addr)) == 0;

    closesocket(sock);
    return is_open;
}

// Function to scan a range of ports concurrently
void scan_ports_concurrently(const string& ip, int start_port, int end_port, int timeout_ms) {
    for (int port = start_port; port <= end_port; ++port) {
        if (scan_port(ip, port, timeout_ms)) {
            cout << GREEN << "[+] Port " << port << " is OPEN" << RESET << endl;
            open_ports++;
        } else {
            cout << RED << "[-] Port " << port << " is CLOSED" << RESET << endl;
        }
    }
}

// Multi-threaded scanning to speed up the process
void multi_threaded_scan(const string& ip, int start_port, int end_port, int timeout_ms, int num_threads) {
    int range = (end_port - start_port + 1) / num_threads;
    vector<thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        int thread_start_port = start_port + i * range;
        int thread_end_port = (i == num_threads - 1) ? end_port : thread_start_port + range - 1;
        threads.emplace_back(scan_ports_concurrently, ip, thread_start_port, thread_end_port, timeout_ms);
    }

    for (auto& t : threads) {
        t.join();
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << RED << "WSAStartup failed.\n" << RESET;
        return 1;
    }

    string ip;
    int start_port, end_port, num_threads, timeout_ms;

    cout << CYAN << "Enter IP to scan: " << RESET;
    cin >> ip;
    cout << CYAN << "Enter start port: " << RESET;
    cin >> start_port;
    cout << CYAN << "Enter end port: " << RESET;
    cin >> end_port;
    cout << CYAN << "Enter number of threads: " << RESET;
    cin >> num_threads;
    cout << CYAN << "Enter timeout in milliseconds: " << RESET;
    cin >> timeout_ms;

    cout << YELLOW << "\nStarting scan on " << ip << " from port " << start_port << " to " << end_port << "...\n" << RESET;

    // Start multi-threaded scan
    multi_threaded_scan(ip, start_port, end_port, timeout_ms, num_threads);

    cout << CYAN << "\nScan complete. Open ports found: " << open_ports.load() << RESET << endl;

    WSACleanup();
    return 0;
}
