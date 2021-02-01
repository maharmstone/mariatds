#include <string>
#include <stdexcept>
#include <thread>
#include <fmt/format.h>

class sockets_error : public std::exception {
public:
    sockets_error(const std::string_view& func) : err(errno), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
    }

    virtual const char* what() const noexcept {
        return msg.c_str();
    }

private:
    int err;
    std::string msg;
};

class formatted_error : public std::exception {
public:
	template<typename T, typename... Args>
	formatted_error(const T& s, Args&&... args) {
		msg = fmt::format(s, std::forward<Args>(args)...);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};

class client_thread {
public:
    client_thread(unsigned int sock) : sock(sock), t([&]() {
        run();
    }) { }

private:
    void run();
    std::string recv(unsigned int len);
    void handle_packet(const std::string_view& packet);

    unsigned int sock;
    std::thread t;
    std::string buf;
    bool open = true;
};

enum class tds_msg : uint8_t {
    sql_batch = 1,
    pretds7_login,
    rpc,
    tabular_result,
    attention_signal = 6,
    bulk_load_data,
    federated_auth_token,
    trans_man_req = 14,
    tds7_login = 16,
    sspi,
    prelogin
};

struct tds_header {
    enum tds_msg type;
    uint8_t status;
    uint16_t length;
    uint16_t spid;
    uint8_t packet_id;
    uint8_t window;
};

static_assert(sizeof(tds_header) == 8, "tds_header has wrong size");
