#include "socket.hpp"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <format>

Socket::Socket(const char *intf) {
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) {
        throw std::runtime_error(std::format("socket: {}", strerror(errno)));
    }

    SetIntfConf(intf);

    sockaddr_ll s_ll = {
        .sll_family     = AF_PACKET,
        .sll_protocol   = htons(ETH_P_ALL),
        .sll_ifindex    = conf_.index,
    };

    if (bind(fd_, (sockaddr*)&s_ll, sizeof(sockaddr_ll)) < 0) {
        throw std::runtime_error(std::format("bind: {}", strerror(errno)));
    }
}

Socket::~Socket(){ 
    if (fd_ >= 0) {
        close(fd_);
    }
}

Buffer Socket::Read() {
    std::cerr << "OK1\n";
    Buffer data(conf_.mtu + 10);
    std::cerr << "OK2\n";
    ssize_t rcnt = read(fd_, data.Data(), data.Capacity());
    if (rcnt <= 0) {
        return data;
    }

    data.SetSize(rcnt);
    return data;
}

void Socket::Write(Buffer &data) {
    write(fd_, data.Data(), data.Size());
}

void Socket::SetIntfConf(const char *intf) {
    std::cout << "Set interface config:\n";
    conf_.name = intf;

    ifreq ifr = {};
    memccpy(ifr.ifr_name, intf, 0, sizeof(ifr.ifr_name));

    std::cout << std::format("\tInterface name: {}\n", ifr.ifr_name);

    if (ioctl(fd_, SIOCGIFADDR, &ifr) < 0) {
        // throw std::runtime_error(std::format(
        //     "ioctl not found IP: {}",
        //     strerror(errno)
        // ));
        std::cout << std::format("\tIP: None\n");
    } else {
        conf_.addr = ((sockaddr_in*)&ifr.ifr_addr)->sin_addr;
        std::cout << std::format("\tIP: {}\n", inet_ntoa(conf_.addr));
    }

    // if (ioctl(fd_, SIOCGIFNETMASK, &ifr) < 0) {
    //     throw std::runtime_error(std::format(
    //         "ioctl not found subnet mask: {}",
    //         strerror(errno)
    //     ));
    // }
    // conf_.mask = (u_long)((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    // std::cout << std::format("\tIP: {}/{}\n", inet_ntoa(conf_.addr), conf_.mask);

    if (ioctl(fd_, SIOCGIFMTU, &ifr) < 0) {
        throw std::runtime_error(std::format(
            "ioctl not found MTU: {}",
            strerror(errno)
        ));
    }
    conf_.mtu = ifr.ifr_mtu;
    std::cout << std::format("\tMTU: {}\n", conf_.mtu);
    
    if (ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        throw std::runtime_error(std::format(
            "ioctl not found interface index: {}",
            strerror(errno)
        ));
    }
    conf_.index = ifr.ifr_ifindex;
    std::cout << std::format("\tIndex: {}\n", conf_.index);
}
