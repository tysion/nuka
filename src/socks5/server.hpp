#pragma once

#include <userver/concurrent/background_task_storage.hpp>
#include <userver/engine/io/socket.hpp>

#include <string>

namespace nuka::socks5 {

class Server {
public:
    Server(std::string bind_address, uint16_t port);

    void Run();

private:
    void HandleClient(userver::engine::io::Socket client_socket);

    std::string bind_address_;
    uint16_t port_;

    userver::concurrent::BackgroundTaskStorage bg_storage_;
};

}  // namespace nuka::socks5
