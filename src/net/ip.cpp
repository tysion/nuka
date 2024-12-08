#include "ip.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>

namespace nuka::net {

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

}  // namespace nuka::net