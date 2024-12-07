#include "server.hpp"

#include <userver/concurrent/background_task_storage.hpp>
#include <userver/engine/task/cancel.hpp>
#include <userver/logging/log.hpp>
#include <userver/utils/encoding/hex.hpp>
#include <userver/utils/ip.hpp>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <chrono>

using namespace std::chrono_literals;

namespace {

userver::engine::io::Sockaddr CreateSockAddrIpV4(const std::string& address, uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &addr.sin_addr);

    return userver::engine::io::Sockaddr(reinterpret_cast<const void*>(&addr));
}

userver::engine::io::Sockaddr CreateSockAddrIpV6(const std::string& address, uint16_t port) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    inet_pton(AF_INET6, address.c_str(), &addr.sin6_addr);

    return userver::engine::io::Sockaddr(reinterpret_cast<const void*>(&addr));
}

userver::engine::io::Sockaddr CreateSockAddrDomain(const std::string& domain, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;  // Поддержка как IPv4, так и IPv6
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    if (getaddrinfo(domain.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
        throw std::runtime_error("Failed to resolve domain name: " + domain);
    }

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> result_guard(result, freeaddrinfo);

    if (result->ai_family == AF_INET) {
        // IPv4
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(result->ai_addr);
        addr->sin_port = htons(port);
        return userver::engine::io::Sockaddr(reinterpret_cast<const void*>(addr));
    } else if (result->ai_family == AF_INET6) {
        // IPv6
        sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(result->ai_addr);
        addr->sin6_port = htons(port);
        return userver::engine::io::Sockaddr(reinterpret_cast<const void*>(addr));
    }

    throw std::runtime_error("Unsupported address family for domain: " + domain);
}

userver::engine::io::Sockaddr CreateSockAddr(const std::string& domain, uint16_t port, uint8_t address_type) {
    switch (address_type) {
        case 0x01: {
            return CreateSockAddrIpV4(domain, port);
        }
        case 0x03: {
            return CreateSockAddrDomain(domain, port);
        }
        case 0x04: {
            return CreateSockAddrIpV6(domain, port);
        }
        default: {
            throw std::runtime_error("Unsupported address type");
        }
    }
    return {};
}

std::string FormatIPv4(const std::array<uint8_t, 4>& ipv4) {
    char buffer[INET_ADDRSTRLEN];
    sockaddr_in addr{};
    std::memcpy(&addr.sin_addr.s_addr, ipv4.data(), ipv4.size());

    if (inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)) == nullptr) {
        throw std::runtime_error("Failed to format IPv4 address");
    }

    return std::string(buffer);
}

std::string FormatIPv6(const std::array<uint8_t, 16>& ipv6) {
    char buffer[INET6_ADDRSTRLEN];
    sockaddr_in6 addr{};
    std::memcpy(addr.sin6_addr.s6_addr, ipv6.data(), ipv6.size());

    if (inet_ntop(AF_INET6, &addr.sin6_addr, buffer, sizeof(buffer)) == nullptr) {
        throw std::runtime_error("Failed to format IPv6 address");
    }

    return std::string(buffer);
}

}  // namespace

namespace nuka::socks5 {

Server::Server(std::string bind_address, uint16_t port) : bind_address_{std::move(bind_address)}, port_{port} {}

void Server::Run() {
    userver::engine::io::Socket server_socket(
        userver::engine::io::AddrDomain::kInet, userver::engine::io::SocketType::kStream
    );
    userver::engine::io::Sockaddr sockaddr = CreateSockAddrIpV4(bind_address_, port_);

    LOG_DEBUG() << "Binding server socket to " << sockaddr;
    server_socket.Bind(sockaddr);
    server_socket.Listen();

    LOG_INFO() << "SOCKS5 server is running on " << sockaddr;

    while (!userver::engine::current_task::ShouldCancel()) {
        try {
            auto client_socket = server_socket.Accept({});
            bg_storage_.AsyncDetach("", [this, client_socket = std::move(client_socket)]() mutable {
                HandleClient(std::move(client_socket));
            });
        } catch (const std::exception& ex) {
            LOG_ERROR() << "Error handling client: " << ex.what();
        }
    }
}

void Server::HandleClient(userver::engine::io::Socket client_socket) {
    try {
        LOG_INFO() << "New client connected";

        const auto deadline = userver::engine::Deadline::FromDuration(10s);
        uint32_t server_address = inet_addr(bind_address_.c_str());
        if (server_address == INADDR_NONE) {
            LOG_ERROR() << "Invalid bind address for SOCKS5 response";
            return;
        }
        server_address = htonl(server_address);
        uint16_t server_port = htons(port_);

        // Step 1: Read the first request from the client (SOCKS5 handshake)
        std::array<uint8_t, 2> handshake_header;
        auto bytes_received = client_socket.ReadAll(handshake_header.data(), handshake_header.size(), deadline);
        LOG_DEBUG() << "Received handshake header: "
                    << userver::utils::encoding::ToHex(handshake_header.data(), handshake_header.size());

        uint8_t socks_version = handshake_header[0];
        if (socks_version != 0x05) {
            LOG_ERROR() << "Unsupported SOCKS version in handshake header: " << static_cast<int>(socks_version);
            return;
        }

        const uint8_t method_count = handshake_header[1];
        std::vector<uint8_t> methods(method_count);
        bytes_received = client_socket.ReadAll(methods.data(), methods.size(), deadline);
        LOG_DEBUG() << "Received methods: " << userver::utils::encoding::ToHex(methods.data(), methods.size());

        // Check if `0x00 NO AUTHENTICATION REQUIRED` actually among methods
        const bool contains_no_auth = std::find(methods.begin(), methods.end(), 0x00) != methods.end();
        if (!contains_no_auth) {
            LOG_ERROR() << "Only '0x00 NO AUTHENTICATION REQUIRED' method is supported";
            std::array<uint8_t, 2> failure_response = {0x05, 0xFF};
            client_socket.SendAll(failure_response.data(), failure_response.size(), deadline);
            return;
        }

        // TODO: accept `0x02 USERNAME/PASSWORD` instead
        // Send handshake response: only "NO AUTHENTICATION REQUIRED" supported
        std::array<uint8_t, 2> handshake_response = {0x05, 0x00};
        size_t bytes_sent = client_socket.SendAll(handshake_response.data(), handshake_response.size(), deadline);

        // Step 2: Read connection request
        std::array<uint8_t, 4> request_header;
        bytes_received = client_socket.ReadAll(request_header.data(), request_header.size(), deadline);
        LOG_DEBUG() << "Received request header: "
                    << userver::utils::encoding::ToHex(request_header.data(), request_header.size());

        socks_version = request_header[0];
        if (socks_version != 0x05) {
            LOG_ERROR() << "Unsupported SOCKS version in request header: " << static_cast<int>(socks_version);
            return;
        }

        const uint8_t command = request_header[1];
        if (command != 0x01) {  // 0x01 = CONNECT
            LOG_ERROR() << "Unsupported command: " << static_cast<int>(command);
            std::array<uint8_t, 10> failure_response = {
                0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };  // Command not supported
            std::memcpy(failure_response.data() + 4, &server_address, 4);
            std::memcpy(failure_response.data() + 8, &server_port, 2);
            client_socket.SendAll(failure_response.data(), failure_response.size(), deadline);
            return;
        }

        // Sterp 3: Determining the address
        const uint8_t address_type = request_header[3];
        std::string target_address;
        uint16_t target_port;

        switch (address_type) {  // Address type
            case 0x01: {         // IPv4
                std::array<uint8_t, 4> ipv4_address;
                bytes_received = client_socket.ReadAll(ipv4_address.data(), ipv4_address.size(), deadline);
                target_address = FormatIPv4(ipv4_address);
                LOG_DEBUG() << "Target address (IPv4): " << target_address;
                break;
            }
            case 0x03: {  // Domain name
                uint8_t domain_length;
                bytes_received = client_socket.ReadAll(&domain_length, 1, deadline);
                target_address.resize(domain_length, '\0');
                bytes_received = client_socket.ReadAll(target_address.data(), target_address.size(), deadline);
                LOG_DEBUG() << "Target address (domain): " << target_address;
                break;
            }
            case 0x04: {  // IPv4
                std::array<uint8_t, 16> ipv6_address;
                bytes_received = client_socket.ReadAll(ipv6_address.data(), ipv6_address.size(), deadline);
                target_address = FormatIPv6(ipv6_address);
                LOG_DEBUG() << "Target address (IPv6): " << target_address;
                break;
            }
            default: {
                LOG_ERROR() << "Unsupported address type: " << static_cast<int>(address_type);
                return;
            }
        }

        std::array<uint8_t, 2> port_bytes;
        bytes_received = client_socket.ReadAll(port_bytes.data(), port_bytes.size(), deadline);
        target_port = (port_bytes[0] << 8) | port_bytes[1];
        LOG_INFO() << "Target port: " << target_port;

        // Step 4: Establish a connection to the target server
        userver::engine::io::Socket target_socket(
            userver::engine::io::AddrDomain::kInet, userver::engine::io::SocketType::kStream
        );
        userver::engine::io::Sockaddr target_sockaddr = CreateSockAddr(target_address, target_port, address_type);
        target_socket.Connect(target_sockaddr, deadline);
        LOG_INFO() << "Connected to target server: " << target_sockaddr;

        std::array<uint8_t, 10> success_response = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        std::memcpy(success_response.data() + 4, &server_address, 4);
        std::memcpy(success_response.data() + 8, &server_port, 2);
        bytes_sent = client_socket.SendAll(success_response.data(), success_response.size(), deadline);
        LOG_INFO() << "Sent SOCKS5 success response: Address=" << bind_address_ << ", Port=" << port_;

        // Step 5: Proxying data
        auto client_to_target_task = userver::engine::AsyncNoSpan([&client_socket, &target_socket, &deadline]() {
            try {
                std::vector<uint8_t> buffer(4096);
                while (true) {
                    const auto bytes_received = client_socket.ReadSome(buffer.data(), buffer.size(), {});
                    if (bytes_received == 0) {
                        LOG_INFO() << "Connection closed by client";
                        break;
                    }
                    const auto bytes_sent = target_socket.SendAll(buffer.data(), bytes_received, deadline);
                }
            } catch (const std::exception& ex) {
                LOG_ERROR() << "Error forwarding data to target: " << ex.what();
            }
        });

        auto target_to_client_task = userver::engine::AsyncNoSpan([&client_socket, &target_socket, &deadline]() {
            try {
                std::vector<uint8_t> buffer(4096);
                while (true) {
                    const auto bytes_received = target_socket.ReadSome(buffer.data(), buffer.size(), {});
                    if (bytes_received == 0) {
                        LOG_INFO() << "Connection closed by target";
                        break;
                    }
                    const auto bytes_sent = client_socket.SendAll(buffer.data(), bytes_received, deadline);
                }
            } catch (const std::exception& ex) {
                LOG_ERROR() << "Error forwarding data to client: " << ex.what();
            }
        });

        client_to_target_task.Wait();
        target_to_client_task.Wait();

    } catch (const std::exception& ex) {
        LOG_ERROR() << "Error handling client: " << ex.what();
    }
}

}  // namespace nuka::socks5