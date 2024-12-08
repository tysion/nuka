#pragma once

#include "net/socket.hpp"

#include <userver/components/tcp_acceptor_base.hpp>

namespace nuka::socks5 {

class Acceptor final : public userver::components::TcpAcceptorBase {
public:
    static constexpr std::string_view kName = "socks5";

    Acceptor(const userver::components::ComponentConfig& config, const userver::components::ComponentContext& context);

    void ProcessSocket(net::Socket::BaseSocket&& client_socket) override;

    static userver::yaml_config::Schema GetStaticConfigSchema();

private:
    void HandleHandshakeRequest(net::Socket::Ptr client_socket, net::Socket::Deadline deadline);
    net::Socket::Ptr HandleConnectionRequest(net::Socket::Ptr client_socket, net::Socket::Deadline deadline);

    const uint16_t port_;
    const std::chrono::seconds timeout_;
};

}  // namespace nuka::socks5
