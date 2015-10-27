#include <iostream>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

using std::map;

namespace UdpForwarder {

const u_short       kSocksServerPort = 9080;

void parse_dns(const char* in, char* out, size_t limit) {
    const char* iptr = in;
    char* optr = out;
    while (*iptr) {
        size_t len = *iptr;
        ++iptr;
        memcpy(optr, iptr, len);
        iptr += len;
        optr += len;
        *optr = '.';
        ++optr;
    }

    --optr;
    *optr = '\0';
}

struct Client {
    int             sock;
    sockaddr_in*    addr;
};

std::map<int, sockaddr_in*> gClients;

int init_ss() {
    int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
    ::sockaddr_in ss_addr;
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(kSocksServerPort);
    ss_addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");

    if (::connect(ss_sock, reinterpret_cast<sockaddr*>(&ss_addr), sizeof(ss_addr)) < 0) {
        ::perror("connect to ss server error");
        return -1;
    }

    return ss_sock;
}

int udp_via_socks(char *data, size_t size) {
#if 0
    int ss_sock = init_ss();
    // Greetings
    const char greeting[] = { 0x05, 0x01, 0x00 };
    ::send(ss_sock, greeting, 3, 0);

    unsigned char res[1000];
    ssize_t rc;
    rc = ::recv(ss_sock, res, sizeof(res), 0);
    if (rc < 0) {
        ::perror("recv associate response");
        ::close(ss_sock);
        return -1;
    }

    printf("UDP associate res size: %ld: ", rc);
    for (int i = 0; i < rc; i++)
        printf("%02x ", res[i]);
    printf("\n");

    // UDP assoc
    char req[10];
    req[0] = '\x05';    // SOCKS v5
    req[1] = '\x03';    // UDP associate
    req[2] = '\x00';    // Reserved
    req[3] = '\x01';    // IPv4
    auto dns_addr = ::inet_addr("8.8.8.8");
    auto dns_port = htons(53);
    std::memcpy(req + 4, static_cast<void*>(&dns_addr), 4);
    std::memcpy(req + 8, static_cast<void*>(&dns_port), 2);

    if ((rc = ::send(ss_sock, req, 10, 0)) < 0) {
        ::perror("send associate request to ss");
        ::close(ss_sock);
        return -1;
    }

    printf("UDP associate request sent: %ld\n", rc);

    rc = ::recv(ss_sock, res, sizeof(res), 0);
    if (rc < 0) {
        ::perror("recv associate response");
        ::close(ss_sock);
        return -1;
    }

    printf("UDP associate res size: %ld: ", rc);
    for (int i = 0; i < rc; i++) {
        printf("%02x ", res[i]);
    }
    printf("\n");
#endif

    // send the real payload
    auto dns_addr = ::inet_addr("8.8.8.8");
    auto dns_port = htons(53);
    data[0] = data[1] = '\x00';   // Reserved
    data[2] = 0;                 // Frag
    data[3] = '\x01';            // IPv4
    std::memcpy(data + 4, static_cast<void*>(&dns_addr), 4);
    std::memcpy(data + 8, static_cast<void*>(&dns_port), 2);

    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ::sockaddr_in ss_addr;
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(kSocksServerPort);
    ss_addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");

    if (::connect(data_sock, reinterpret_cast<sockaddr*>(&ss_addr), sizeof(ss_addr)) < 0) {
        ::perror("connect to ss server error");
        return -1;
    }

    ssize_t sent = ::send(data_sock, data, size, 0);
    if (sent < 0) {
        ::perror("send payload to ss server error");
        return -1;
    }

    //printf("UDP payload sent: %ld\n", sent);
    return data_sock;
}

#if 0
int plain_forward(void *data, size_t size) {
    // parse/validate request

    int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ::sockaddr_in ss_addr;
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(53);
    ss_addr.sin_addr.s_addr = ::inet_addr("114.114.114.114");

    if (::connect(dns_sock, reinterpret_cast<sockaddr*>(&ss_addr), sizeof(ss_addr)) < 0) {
        ::perror("connect to ss server error");
        return -1;
    }

    ssize_t rc;
    if ((rc = ::send(dns_sock, data, size, 0)) < 0) {
        ::perror("send dns request to server");
        ::close(dns_sock);
        return -1;
    }

    printf("DNS request sent: %ld\n", rc);
    return dns_sock;
}
#endif

int run(u_short port) {
    // listen sock
    int listen_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    ::sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::perror("bind");
        return -1;
    }

    std::size_t buflen = 65536;
    auto buf = static_cast<char*>(std::malloc(buflen));

    for (;;) {
        ::pollfd fds[10000];
        fds[0].fd = listen_sock;
        fds[0].events = POLLIN;

        // add all sockets from gClients
        int client_count = 0;
        for (const auto& client : gClients) {
            ++client_count;
            fds[client_count].fd = client.first;
            fds[client_count].events = POLLIN;
        }

        std::cout << "Total clients: " << client_count << std::endl;

        int rc = ::poll(fds, client_count + 1, -1);
        if (rc < 0) {
            ::perror("poll");
            break;
        }

        printf("========= poll=%d =========\n", rc);
        // request
        if (fds[0].revents) {
            ::sockaddr_in from;
            ::socklen_t addrlen = sizeof(from);
            char* ptr = buf + 10;
            size_t limit = buflen - 10;
            ssize_t rsize = ::recvfrom(listen_sock, ptr, limit, 0,
                                       reinterpret_cast<sockaddr*>(&from),
                                       &addrlen);
            if (rsize < 0) {
                ::perror("recvfrom");
                break;
            }

            std::cout << "Got " << rsize << " bytes from client: "
                      << ntohs(from.sin_port) << "/" << addrlen <<  std::endl;

            char hostname[256];
            parse_dns(ptr + 12, hostname, sizeof(hostname)); 
            printf("dns: [%s]\n", hostname);

            // int sock = plain_forward(ptr, rsize);
            int sock = udp_via_socks(buf, rsize + 10);
            if (sock < 0) {
                break;
            }

            gClients[sock] = new sockaddr_in(from);
        }

        // response
        for (int i = 1; i <= client_count; i++) {
            if (fds[i].revents) {
                int sock = fds[i].fd;
                ::sockaddr_in from;
                ::socklen_t addrlen;
                ssize_t rsize = ::recvfrom(sock, buf, buflen, 0,
                                           reinterpret_cast<sockaddr*>(&from),
                                           &addrlen);
                if (rsize < 0) {
                    ::perror("recvfrom");
                    break;
                }
        
                auto client = gClients[sock];
                char ip[20];
                ::inet_ntop(AF_INET, &client->sin_addr, ip, 20);
                std::cout << "Got " << rsize << " bytes for client "
                          << ip << ":" << ntohs(client->sin_port) << std::endl;
#if 0
                for (int i = 0; i < rsize; i++)
                    printf("%02x ", (uint8_t)buf[i]);
                printf("\n");
#endif

                ssize_t sent;
                sent = ::sendto(listen_sock, buf + 10, rsize - 10, 0,
                                reinterpret_cast<sockaddr*>(client),
                                sizeof(*client));
                if (sent != rsize - 10) {
                    std::cerr << "fwd to client " << listen_sock << ": "
                              << strerror(errno) << std::endl; 
                    break;
                }

                std::cout << "Reply fwd'd: " << sent << std::endl;
                gClients.erase(sock);
                delete client;
                ::close(sock);
            }
        }
    }

    std::free(buf);
    std::cerr << "error in main loop, quitting ..." << std::endl;
    return -1;
}

}       // namespace

int main(int argc, char* argv[]) {
    u_short port = 1953;
    if (argc > 1)
        port = atoi(argv[1]);

    return UdpForwarder::run(port);
}
