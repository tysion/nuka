#include "acceptor.hpp"
#include "net/ip.hpp"
#include "net/sockaddr.hpp"

#include <userver/components/component_config.hpp>
#include <userver/engine/task/cancel.hpp>
#include <userver/engine/wait_all_checked.hpp>
#include <userver/logging/log.hpp>
#include <userver/utils/encoding/hex.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <arpa/inet.h>

#include <chrono>

using namespace std::chrono_literals;

namespace nuka::socks5 {

using userver::utils::encoding::ToHex;

static constexpr uint8_t kSocksVersion = 0x05;

// methods
static constexpr uint8_t kNoAuthenticationRequired = 0x00;
static constexpr uint8_t kNoAcceptableMethods = 0xFF;

// address type
static constexpr uint8_t kAtypIpV4 = 0x01;
static constexpr uint8_t kAtypDomainName = 0x03;
static constexpr uint8_t kAtypIpV6 = 0x04;

// commands
static constexpr uint8_t kCmdConnect = 0x01;
static constexpr uint8_t kCmdUdpAssociate = 0x03;

// reply field
static constexpr uint8_t kRepSucceeded = 0x00;
static constexpr uint8_t kRepCommandNotSupported = 0x07;

Acceptor::Acceptor(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context
)
    : TcpAcceptorBase(config, context),
      port_{config["port"].As<uint16_t>()},
      timeout_{config["timeout"].As<std::chrono::seconds>()} {}

void Acceptor::HandleHandshakeRequest(net::Socket::Ptr client_socket, net::Socket::Deadline deadline) {
    std::array<uint8_t, 2> header;
    client_socket->ReadAll(header, deadline);
    LOG_DEBUG() << "Received handshake header: " << ToHex(header.data(), header.size());

    const uint8_t socks_version = header[0];
    if (socks_version != kSocksVersion) {
        LOG_ERROR() << "Unsupported SOCKS version in handshake header: " << static_cast<int>(socks_version);
        throw std::runtime_error("Unsupported SOCKS version");
    }

    const uint8_t method_count = header[1];
    std::vector<uint8_t> methods(method_count);
    client_socket->ReadAll(methods, deadline);
    LOG_DEBUG() << "Received methods: " << ToHex(methods.data(), methods.size());

    if (std::find(methods.begin(), methods.end(), kNoAuthenticationRequired) == methods.end()) {
        LOG_ERROR() << "Only '0x00 NO AUTHENTICATION REQUIRED' method is supported";
        std::array<uint8_t, 2> response = {kSocksVersion, kNoAcceptableMethods};
        client_socket->SendAll(response, deadline);
        throw std::runtime_error("No acceptable methods");
    }

    std::array<uint8_t, 2> response = {kSocksVersion, kNoAuthenticationRequired};
    client_socket->SendAll(response, deadline);
}

std::string DetermineTargetAddress(net::Socket::Ptr socket, uint8_t address_type, net::Socket::Deadline deadline) {
    std::string target_address;

    switch (address_type) {
        case kAtypIpV4: {
            std::array<uint8_t, 4> ipv4_address;
            socket->ReadAll(ipv4_address, deadline);
            target_address = net::FormatIPv4(ipv4_address);
            LOG_DEBUG() << "Target address (IPv4): " << target_address;
            break;
        }
        case kAtypDomainName: {
            uint8_t domain_length;
            socket->ReadAll({&domain_length, 1}, deadline);
            target_address.resize(domain_length, '\0');
            socket->ReadAll({reinterpret_cast<uint8_t*>(target_address.data()), target_address.size()}, deadline);
            LOG_DEBUG() << "Target address (domain): " << target_address;
            break;
        }
        case kAtypIpV6: {
            std::array<uint8_t, 16> ipv6_address;
            socket->ReadAll(ipv6_address, deadline);
            target_address = net::FormatIPv6(ipv6_address);
            LOG_DEBUG() << "Target address (IPv6): " << target_address;
            break;
        }
        default: {
            LOG_ERROR() << "Unsupported address type: " << static_cast<int>(address_type);
            throw std::runtime_error("Unsupported address type");
        }
    }

    return target_address;
}

uint16_t DetermineTargetPort(net::Socket::Ptr socket, net::Socket::Deadline deadline) {
    std::array<uint8_t, 2> port_bytes;
    socket->ReadAll(port_bytes, deadline);
    auto target_port = (port_bytes[0] << 8) | port_bytes[1];
    LOG_DEBUG() << "Target port: " << target_port;
    return target_port;
}

net::Socket::Ptr Acceptor::HandleConnectionRequest(net::Socket::Ptr client_socket, net::Socket::Deadline deadline) {
    const uint32_t server_address = htonl(inet_addr("0.0.0.0"));
    const uint16_t server_port = htons(port_);

    std::array<uint8_t, 4> header;
    client_socket->ReadAll(header, deadline);
    LOG_DEBUG() << "Received request header: " << ToHex(header.data(), header.size());

    const uint8_t socks_version = header[0];
    if (socks_version != kSocksVersion) {
        LOG_ERROR() << "Unsupported SOCKS version in request header: " << static_cast<int>(socks_version);
        throw std::runtime_error("Unsupported SOCKS version");
    }

    const uint8_t command = header[1];
    if (command != kCmdConnect) {
        LOG_ERROR() << "Unsupported command: " << static_cast<int>(command);
        std::array<uint8_t, 10> response = {
            kSocksVersion, kRepCommandNotSupported, 0x00, kAtypIpV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        std::memcpy(response.data() + 4, &server_address, 4);
        std::memcpy(response.data() + 8, &server_port, 2);
        client_socket->SendAll(response, deadline);

        throw std::runtime_error("Unsupported command");
    }

    userver::engine::io::SocketType socket_type{userver::engine::io::SocketType::kStream};
    if (command == kCmdConnect) {
        socket_type = userver::engine::io::SocketType::kStream;
    } else if (command == kCmdUdpAssociate) {
        socket_type = userver::engine::io::SocketType::kDgram;
    }

    const auto target_address_type = header[3];
    const auto target_address = DetermineTargetAddress(client_socket, target_address_type, deadline);
    const auto target_port = DetermineTargetPort(client_socket, deadline);

    std::array<uint8_t, 10> response = {
        kSocksVersion, kRepSucceeded, 0x00, kAtypIpV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    std::memcpy(response.data() + 4, &server_address, 4);
    std::memcpy(response.data() + 8, &server_port, 2);
    client_socket->SendAll(response, deadline);

    auto socket_address = net::CreateSockAddr(target_address, target_port, target_address_type);
    auto target_socket = net::Socket::BaseSocket(userver::engine::io::AddrDomain::kInet, socket_type);
    target_socket.Connect(socket_address, deadline);
    LOG_INFO() << "Connected to target server: " << socket_address;
    // UASSERT(target_socket.IsValid());

    return std::make_shared<net::TcpSocket>(std::move(target_socket));
}

void ProcessClientToTarget(net::Socket::Ptr client_socket, net::Socket::Ptr target_socket) {
    try {
        std::vector<uint8_t> buffer(4096);
        while (!userver::engine::current_task::ShouldCancel()) {
            const auto bytes_received = client_socket->ReadSome(buffer, {});
            if (bytes_received == 0) {
                LOG_INFO() << "Connection closed by client";
                break;
            }

            const auto deadline = net::Socket::Deadline::FromDuration(1s);
            target_socket->SendAll({buffer.data(), bytes_received}, deadline);
        }
    } catch (const std::exception& ex) {
        LOG_ERROR() << "Error forwarding data to target: " << ex.what();
    }
}

void ProcessTargetToClient(net::Socket::Ptr client_socket, net::Socket::Ptr target_socket) {
    try {
        std::vector<uint8_t> buffer(4096);
        while (!userver::engine::current_task::ShouldCancel()) {
            const auto bytes_received = target_socket->ReadSome(buffer, {});
            if (bytes_received == 0) {
                LOG_INFO() << "Connection closed by target";
                break;
            }
            const auto deadline = net::Socket::Deadline::FromDuration(1s);
            client_socket->SendAll({buffer.data(), bytes_received}, deadline);
        }
    } catch (const std::exception& ex) {
        LOG_ERROR() << "Error forwarding data to client: " << ex.what();
    }
}

void Acceptor::ProcessSocket(net::Socket::BaseSocket&& socket) {
    try {
        const auto deadline = userver::engine::Deadline::FromDuration(timeout_);

        auto client_socket = std::make_shared<net::TcpSocket>(std::move(socket));

        // Step 1: Read the first request from the client (SOCKS5 handshake)
        HandleHandshakeRequest(client_socket, deadline);

        // Step 2: Read connection request
        auto target_socket = HandleConnectionRequest(client_socket, deadline);

        // Step 3: Proxying data
        auto client_to_target_task = userver::engine::AsyncNoSpan([client_socket, target_socket]() mutable {
            return ProcessClientToTarget(client_socket, target_socket);
        });
        auto target_to_client_task = userver::engine::AsyncNoSpan([client_socket, target_socket]() mutable {
            return ProcessTargetToClient(client_socket, target_socket);
        });

        userver::engine::WaitAllChecked(client_to_target_task, target_to_client_task);
    } catch (const std::exception& ex) {
        LOG_ERROR() << "Exception caught during processing the socket: " << ex.what();
    }
}

userver::yaml_config::Schema Acceptor::GetStaticConfigSchema() {
    return userver::yaml_config::MergeSchemas<userver::components::TcpAcceptorBase>(R"(
        type: object
        description: SOCKS5 component
        additionalProperties: false
        properties:
            timeout:
                type: string
                description: time to handle handshake and connect requests
  )");
}

}  // namespace nuka::socks5
