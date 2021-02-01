#include <string>
#include <stdexcept>
#include <thread>

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

class client_thread {
public:
    client_thread(unsigned int sock) : sock(sock), t([&]() {
        run();
    }) { }

private:
    void run();

    unsigned int sock;
    std::thread t;
};
