#pragma once

#include <userver/engine/io/socket.hpp>
#include <userver/logging/log_extra.hpp>
#include <userver/utils/span.hpp>

namespace nuka::net {

class Socket {
public:
    using Type = userver::engine::io::SocketType;
    using BaseSocket = userver::engine::io::Socket;
    using Deadline = userver::engine::Deadline;
    using Sockaddr = userver::engine::io::Sockaddr;
    using Ptr = std::shared_ptr<Socket>;

    template <typename T>
    using Span = userver::utils::span<T>;

    size_t ReadSome(Span<uint8_t> data, Deadline deadline);
    size_t ReadAll(Span<uint8_t> data, Deadline deadline);
    virtual size_t SendAll(Span<const uint8_t> data, Deadline deadline) = 0;
    Type GetType() const;
    const Socket::Sockaddr& GetSockaddr();

    Socket(BaseSocket socket, Type socket_type);
    virtual ~Socket() = default;

protected:
    BaseSocket socket_;
    Type socket_type_;
    userver::logging::LogExtra log_extra_;
};

class TcpSocket final : public Socket {
public:
    static constexpr auto kType = Type::kStream;

    TcpSocket(BaseSocket socket);

    size_t SendAll(Span<const uint8_t> data, Deadline deadline) override;
};

class UdpSocket final : public Socket {
public:
    static constexpr auto kType = userver::engine::io::SocketType::kDgram;

    UdpSocket(userver::engine::io::Socket socket, Sockaddr socket_address);

    size_t SendAll(Span<const uint8_t> data, Deadline deadline) override;

private:
    const Sockaddr socket_address_;
};

}  // namespace nuka::net