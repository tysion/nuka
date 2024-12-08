#include "sockaddr.hpp"

#include <arpa/inet.h>
#include <netdb.h>

namespace nuka::net {

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
    hints.ai_family = AF_UNSPEC;
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

}  // namespace nuka::net