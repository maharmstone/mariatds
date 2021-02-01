#include "mariatds.h"
#include <sys/socket.h>
#include <unistd.h>
#include <codecvt>

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

void client_thread::prelogin_msg(const string_view& packet) {
    string_view sv = packet;
    vector<login_opt> in_opts, out_opts;

    // FIXME - make sure not already logged on

    while (true) {
        if (!sv.empty() && (enum tds_login_opt_type)sv[0] == tds_login_opt_type::terminator)
            break;

        if (sv.length() < sizeof(tds_login_opt))
            throw runtime_error("Malformed prelogin request.");

        auto opt = *(tds_login_opt*)sv.data();
        opt.offset = __builtin_bswap16(opt.offset);
        opt.length = __builtin_bswap16(opt.length);

        if (opt.length != 0) {
            if (opt.offset > packet.length() || opt.offset + opt.length > packet.length())
                throw runtime_error("Malformed prelogin request.");

            in_opts.emplace_back(opt.type, packet.substr(opt.offset, opt.length));
        } else
            in_opts.emplace_back(opt.type, "");

        sv = sv.substr(sizeof(tds_login_opt));
    }

    for (const auto& opt : in_opts) {
        switch (opt.type) {
            case tds_login_opt_type::version: {
                if (opt.payload.length() < sizeof(tds_login_opt_version))
                    throw formatted_error(FMT_STRING("Version option was {} bytes, expected {}."), opt.payload.length(), sizeof(tds_login_opt_version));

                tds_login_opt_version out_ver;

                out_ver.major = 15;
                out_ver.minor = 0;
                out_ver.build = __builtin_bswap16(4033);
                out_ver.subbuild = 0;

                out_opts.emplace_back(tds_login_opt_type::version, string_view((char*)&out_ver, sizeof(out_ver)));
                break;
            }

            case tds_login_opt_type::encryption: {
                if (opt.payload.length() < sizeof(enum tds_encryption_type))
                    throw formatted_error(FMT_STRING("Encryption option was {} bytes, expected {}."), opt.payload.length(), sizeof(enum tds_encryption_type));

                auto enc = (enum tds_encryption_type)opt.payload[0];

                if (enc != tds_encryption_type::ENCRYPT_OFF && enc != tds_encryption_type::ENCRYPT_NOT_SUP)
                    throw runtime_error("Encryption not supported.");

                out_opts.emplace_back(tds_login_opt_type::encryption, string_view("\x02", 1)); // ENCRYPT_NOT_SUP

                break;
            }

            case tds_login_opt_type::instopt:
                out_opts.emplace_back(tds_login_opt_type::instopt, string_view("\x00", 1));
                break;

            case tds_login_opt_type::threadid:
                out_opts.emplace_back(tds_login_opt_type::threadid, "");
                break;

            case tds_login_opt_type::mars:
                out_opts.emplace_back(tds_login_opt_type::mars, string_view("\x00", 1)); // MARS is off
                break;

            default:
                break;
        }
    }

    size_t len = sizeof(enum tds_login_opt_type);
    unsigned int num_opts = 0;

    for (const auto& opt : out_opts) {
        len += sizeof(tds_login_opt);
        len += opt.payload.length();
        num_opts++;
    }

    string ret;

    ret.resize(len);

    auto oh = (tds_login_opt*)ret.data();
    auto ptr = ret.data() + (num_opts * sizeof(tds_login_opt)) + sizeof(enum tds_login_opt_type);

    for (const auto& opt : out_opts) {
        oh->type = opt.type;
        oh->offset = __builtin_bswap16((uint16_t)(ptr - ret.data()));
        oh->length = __builtin_bswap16((uint16_t)opt.payload.length());

        if (!opt.payload.empty()) {
            memcpy(ptr, opt.payload.data(), opt.payload.length());
            ptr += opt.payload.length();
        }

        oh++;
    }

    oh->type = tds_login_opt_type::terminator;

    send_msg(tds_msg::tabular_result, ret);
}

void client_thread::handle_packet(const string_view& packet) {
    auto& h = *(tds_header*)packet.data();

    switch (h.type) {
        case tds_msg::prelogin:
            prelogin_msg(packet.substr(sizeof(tds_header), h.length - sizeof(tds_header)));
            break;

        default:
            throw formatted_error(FMT_STRING("Unhandled packet type {}."), h.type);
    }
}

void client_thread::send_msg(enum tds_msg type, const string_view& data) {
    string packet;

    packet.resize(sizeof(tds_header) + data.length());

    auto& h = *(tds_header*)packet.data();

    h.type = type;
    h.status = 1;
    h.length = __builtin_bswap16((uint16_t)(sizeof(tds_header) + data.length()));
    h.spid = spid;
    h.packet_id = 0;
    h.window = 0;

    memcpy(packet.data() + sizeof(tds_header), data.data(), data.length());

    send(sock, packet.data(), packet.length(), 0);
}

static u16string utf8_to_utf16(const string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.from_bytes(sv.data(), sv.data() + sv.length());
}

static string info_msg(bool error, int32_t msgno, uint8_t state, uint8_t severity,
                       const string_view& msg, const string_view& server, const string_view& proc,
                       uint32_t line_no) {
    string ret;
    auto msg_us = utf8_to_utf16(msg);
    auto server_us = utf8_to_utf16(server);
    auto proc_us = utf8_to_utf16(proc);
    size_t len = sizeof(tds_info_msg) +
                 sizeof(uint16_t) + (msg_us.length() * sizeof(char16_t)) +
                 sizeof(uint8_t) + (server_us.length() * sizeof(char16_t)) +
                 sizeof(uint8_t) + (proc_us.length() * sizeof(char16_t)) +
                 sizeof(uint32_t);

    ret.resize(sizeof(enum tds_token) + sizeof(uint16_t) + len);

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = error ? tds_token::TDS_ERROR : tds_token::INFO;
    ptr += sizeof(enum tds_token);

    *(uint16_t*)ptr = (uint16_t)len; ptr += sizeof(uint16_t);

    auto h = (tds_info_msg*)ptr;

    h->msgno = msgno;
    h->state = state;
    h->severity = severity;

    ptr += sizeof(tds_info_msg);

    *(uint16_t*)ptr = (uint16_t)msg_us.length(); ptr += sizeof(uint16_t);
    memcpy(ptr, msg_us.data(), msg_us.length() * sizeof(char16_t));
    ptr += msg_us.length() * sizeof(char16_t);

    *(uint8_t*)ptr = (uint8_t)server_us.length(); ptr += sizeof(uint8_t);
    memcpy(ptr, server_us.data(), server_us.length() * sizeof(char16_t));
    ptr += server_us.length() * sizeof(char16_t);

    *(uint8_t*)ptr = (uint8_t)proc_us.length(); ptr += sizeof(uint8_t);
    memcpy(ptr, proc_us.data(), proc_us.length() * sizeof(char16_t));
    ptr += proc_us.length() * sizeof(char16_t);

    *(uint32_t*)ptr = line_no;

    return ret;
}

void client_thread::send_error(const string_view& msg) {
    send_msg(tds_msg::tabular_result, info_msg(true, 0, 0, 14, msg, "", "", 0)); // FIXME - server name
}

void client_thread::run() {
    try {
        thread_id = this_thread::get_id();

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
    } catch (const exception& e) {
        try {
            if (open)
                send_error(e.what());
        } catch (...) {
        }
    }

    thread del_thread([&]() {
        unique_lock<shared_mutex> guard(client_threads_mutex);

        for (auto it = client_threads.begin(); it != client_threads.end(); it++) {
            if (it->thread_id == thread_id) {
                client_threads.erase(it);
                break;
            }
        }
    });

    del_thread.detach();
}

client_thread::~client_thread() {
    close(sock);
    t.join();
}
