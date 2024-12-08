#pragma once

#include <userver/engine/io/sockaddr.hpp>

namespace nuka::net {

userver::engine::io::Sockaddr CreateSockAddrIpV4(const std::string& address, uint16_t port);
userver::engine::io::Sockaddr CreateSockAddrIpV6(const std::string& address, uint16_t port);
userver::engine::io::Sockaddr CreateSockAddrDomain(const std::string& domain, uint16_t port);
userver::engine::io::Sockaddr CreateSockAddr(const std::string& domain, uint16_t port, uint8_t address_type);

}  // namespace nuka::net