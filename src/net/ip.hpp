#pragma once

#include <array>
#include <string>

namespace nuka::net {

std::string FormatIPv4(const std::array<uint8_t, 4>& ipv4);
std::string FormatIPv6(const std::array<uint8_t, 16>& ipv6);

}  // namespace nuka::net