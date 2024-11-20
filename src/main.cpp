#include <iostream>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include <unistd.h>
#include <socket.hpp>
#include <format>
#include "filter.hpp"

struct Args {
    const char* inrf0;
    const char* inrf1;
    const char* rule_path;
};


Args ParseArgs(int argc, const char* argv[]) {
    if (argc != 4) {
        std::cout << "Uasge: Firewall <Interface name 0> <Interface name 1> <Path to rules file>\n";
        std::runtime_error("Uncorrect arguments");
    }

    return Args({
        argv[1],
        argv[2],
        argv[3],
    });
}

int main(int argc, const char* argv[]) {
    try {
        auto args = ParseArgs(argc, argv);

        Filter filter(args.rule_path);

        Socket eth0(args.inrf0);
        Socket eth1(args.inrf1);

        pid_t pid = fork();
        switch (pid) {
        case -1: {
            perror("fork: ");
        } break;

        case 0: {
            while (true) {
                Bridge(eth0, eth1, filter);
            }
        } break;
        
        default:
            while (true) {
                Bridge(eth1, eth0, filter);
            }
            break;
        }

    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}