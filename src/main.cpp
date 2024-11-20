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

int main() {
    try {
        Socket eth0("eth0");
        Socket eth1("eth1");

        pid_t pid = fork();
        switch (pid) {
        case -1: {
            perror("fork: ");
        } break;

        case 0: {
            while (true) {
                auto data = eth0.Read();
                std::cout << "From eth0 to eth1:\n";
                for (int k = 0; k < data.Size(); ++k) {
                    std::cout << std::format("{:02x} ", data.Data()[k]);
                }
                std::cout << "\n";
                eth1.Write(data);
            }
        } break;
        
        default:
            while (true) {
                auto data = eth1.Read();
                std::cout << "From eth1 to eth0:\n";
                for (int k = 0; k < data.Size(); ++k) {
                    std::cout << std::format("{:02x} ", data.Data()[k]);
                }
                std::cout << "\n";
                eth0.Write(data);
            }
            break;
        }

    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}