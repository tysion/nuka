#include "socket.hpp"

#include <userver/logging/log.hpp>
#include <userver/utils/trivial_map.hpp>

namespace nuka::net {

constexpr userver::utils::TrivialBiMap kColorSwitch = [](auto selector) {
    return selector()
        .Case(userver::engine::io::SocketType::kStream, "tcp")
        .Case(userver::engine::io::SocketType::kDgram, "udp")
        .Case(userver::engine::io::SocketType::kTcp, "tcp")
        .Case(userver::engine::io::SocketType::kUdp, "udp");
};

Socket::Socket(userver::engine::io::Socket socket, userver::engine::io::SocketType socket_type)
    : socket_{std::move(socket)}, socket_type_{socket_type} {
    UASSERT(socket_.IsValid());
    log_extra_.Extend("fd", socket_.Fd());
    log_extra_.Extend("sockname", socket_.Getsockname().PrimaryAddressString());
    log_extra_.Extend("peername", socket_.Getpeername().PrimaryAddressString());
    log_extra_.Extend("port", socket_.Getsockname().Port());
    log_extra_.Extend("type", std::string(kColorSwitch.TryFind(socket_type_).value_or("unknown")));
}

size_t Socket::ReadSome(Span<uint8_t> data, Deadline deadline) {
    const auto bytes_received = socket_.RecvSome(data.data(), data.size(), deadline);
    LOG_DEBUG() << log_extra_ << "Received bytes count: " << bytes_received;
    return bytes_received;
}

size_t Socket::ReadAll(Span<uint8_t> data, Deadline deadline) {
    const auto bytes_received = socket_.RecvAll(data.data(), data.size(), deadline);
    LOG_DEBUG() << log_extra_ << "Received bytes count: " << bytes_received;
    return bytes_received;
}

const Socket::Sockaddr& Socket::GetSockaddr() { return socket_.Getsockname(); }

Socket::Type Socket::GetType() const { return socket_type_; }

TcpSocket::TcpSocket(userver::engine::io::Socket socket) : Socket(std::move(socket), kType) {}

size_t TcpSocket::SendAll(Span<const uint8_t> data, Deadline deadline) {
    const auto bytes_sent = socket_.SendAll(data.data(), data.size(), deadline);
    LOG_DEBUG() << log_extra_ << "Sent bytes count: " << bytes_sent;
    return bytes_sent;
}

UdpSocket::UdpSocket(userver::engine::io::Socket socket, Sockaddr socket_address)
    : Socket(std::move(socket), kType), socket_address_{socket_address} {}

size_t UdpSocket::SendAll(Span<const uint8_t> data, Deadline deadline) {
    const auto bytes_sent = socket_.SendAllTo(socket_address_, data.data(), data.size(), deadline);
    LOG_DEBUG() << log_extra_ << "Sent bytes count: " << bytes_sent;
    return bytes_sent;
}

}  // namespace nuka::net