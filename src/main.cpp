#include "socks5/server.hpp"

#include <userver/engine/run_standalone.hpp>
#include <userver/logging/log.hpp>
#include <userver/logging/logger.hpp>

int main(int argc, char* argv[]) {
    try {
        auto logger = userver::logging::MakeStdoutLogger(
            "default", userver::logging::Format::kRaw, userver::logging::Level::kDebug
        );
        userver::logging::impl::SetDefaultLoggerRef(*logger);

        if (argc != 3) {
            LOG_ERROR() << "Usage: " << argv[0] << " <bind_address> <port>\n";
            return EXIT_FAILURE;
        }

        const std::string bind_address = argv[1];
        const uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));

        LOG_INFO() << "Starting SOCKS5 server on " << bind_address << ":" << port;

        userver::engine::RunStandalone(4, [&] {
            nuka::socks5::Server server(bind_address, port);
            server.Run();
        });

        LOG_INFO() << "SOCKS5 server shutdown.";
    } catch (const std::exception& ex) {
        LOG_ERROR() << "Fatal error: " << ex.what();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
