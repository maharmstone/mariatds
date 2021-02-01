#include "mariatds.h"
#include <sys/socket.h>

using namespace std;

string client_thread::recv(unsigned int len) {
    string s;
    int bytes, err = 0;

    if (len == 0)
        len = 4096;

    s.resize(len);

    do {
        bytes = (int)::recv(sock, s.data(), len, 0);

        if (bytes == -1)
            err = errno;
    } while (bytes == -1 && err == EWOULDBLOCK);

    if (bytes == 0 || (bytes == -1 && err == ECONNRESET)) {
        open = false;
        return "";
    } else if (bytes == -1)
        throw formatted_error(FMT_STRING("recv failed ({})"), err);

    return s.substr(0, bytes);
}

void client_thread::handle_packet(const string_view& packet) {
    fmt::print("FIXME - handle packet\n");
}

void client_thread::run() {
    while (open) {
        while (buf.length() < sizeof(tds_header)) {
            buf += recv((unsigned int)(sizeof(tds_header) - buf.length()));

            if (!open)
                break;
        }

        auto& h = *(tds_header*)buf.data();
        uint16_t len = __builtin_bswap16(h.length);

        if (len < sizeof(tds_header))
            throw formatted_error(FMT_STRING("Packet length was {}, expected at least {}."), len, sizeof(tds_header));

        while (buf.length() < len) {
            buf += recv((unsigned int)(len - buf.length()));

            if (!open)
                break;
        }

        // FIXME - large packets

        handle_packet(string_view(buf).substr(0, len));

        buf = buf.substr(len);
    }

    // FIXME - remove from client_threads list
}
