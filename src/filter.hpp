#pragma once
#include "socket.hpp"
#include <vector>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netdb.h>
#include "buffer.hpp"

class Filter {
private:
    struct Rule {
        size_t id_;
        enum {
            kWhite = 0,
            kBlack = 1,
        } type_;
        in_addr_t src_ip_;
        in_addr_t dst_ip_;
        int src_port_;
        int dst_port_;
        struct protoent proto_;
    };

    std::vector<Rule> rules_;

    ethhdr ParseEther(size_t& ptr, Buffer& data);
    iphdr  ParseIP(size_t& ptr, Buffer& data);
    udphdr ParseUDP(size_t& ptr, Buffer& data);
    tcphdr ParseTCP(size_t& ptr, Buffer& data);
public:
    Filter(const char* file_path);
    
    bool operator()(Buffer& buff);
};

void Bridge(Socket& in, Socket& out, Filter& filter);