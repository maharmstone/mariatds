#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <stdexcept>

#define PORT 1433
#define BACKLOG 10

using namespace std;

class sockets_error : public exception {
public:
    sockets_error(const char* func) : err(errno), msg(string(func) + " failed (error " + to_string(err) + ")") {
    }

    virtual const char* what() const noexcept {
        return msg.c_str();
    }

private:
    int err;
    string msg;
};

static void run_server() {
    struct sockaddr_in6 server_addr;
    unsigned int sock;
    int reuseaddr = 1;
    int ipv6only = 0;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(PORT);
    server_addr.sin6_addr = in6addr_any;

    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == 0)
        throw runtime_error("socket failed");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&reuseaddr), sizeof(int)) == -1)
        throw sockets_error("setsockopt");

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&ipv6only), sizeof(int)) == -1)
        throw sockets_error("setsockopt");

    if (bind(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
        throw sockets_error("bind");

    if (listen(sock, BACKLOG) == -1)
        throw sockets_error("listen");

    while (true) {
        struct sockaddr_in6 client_addr;
        int newsock;
        socklen_t size = sizeof(client_addr);

        newsock = accept(sock, reinterpret_cast<sockaddr*>(&client_addr), &size);

        if (newsock == -1)
            throw sockets_error("accept");
    }
}

int main() {
    try {
        run_server();
    } catch (const exception& e) {
        fprintf(stderr, "%s\n", e.what());
        return 1;
    }

    return 0;
}
