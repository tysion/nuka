#include "socks5/acceptor.hpp"

#include <userver/components/minimal_component_list.hpp>
#include <userver/utils/daemon_run.hpp>

int main(int argc, const char* const argv[]) {
    const auto component_list = userver::components::MinimalComponentList().Append<nuka::socks5::Acceptor>();

    return userver::utils::DaemonMain(argc, argv, component_list);
}