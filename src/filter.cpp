#include "filter.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <format>

std::string ctomac(const char* mac) {
    return std::format(
        "{:02x}.{:02x}.{:02x}.{:02x}.{:02x}.{:02x}"
      , mac[0]
      , mac[1]
      , mac[2]
      , mac[3]
      , mac[4]
      , mac[5]
    );
}

void Bridge(Socket &in, Socket &out, Filter& filter) {
    auto data = in.Read();
    std::cout << std::format("Received packet in {}\n", in.IntfName());
    for (int k = 0; k < data.Size(); ++k) {
        std::cout << std::format("{:02x}{}", data.Data()[k], (k + 1) % 10 == 0 ? '\n' : ' ');
    }
    std::cout << "\n";

    auto filt_res = filter(data);

    std::cout << std::format("Filter decision: {}\n\n", filt_res ? std::format("SEND {}", out.IntfName()) : "DROP");
    
    if (filt_res) {
        out.Write(data);
    }
}

ethhdr Filter::ParseEther(size_t& ptr, Buffer& data) {
    if (ptr + sizeof(ethhdr) >= data.Size()) {
        throw std::runtime_error("Expected Ether");
    }
    ethhdr hdr = *(ethhdr*)(data.Data() + ptr);
    hdr.h_proto = ntohs(hdr.h_proto);
    ptr += sizeof(ethhdr);
    return hdr;
}

iphdr Filter::ParseIP(size_t &ptr, Buffer &data) {
    if (ptr + sizeof(iphdr) >= data.Size()) {
        throw std::runtime_error("Expected IPv4");
    }
    iphdr hdr = *(iphdr*)(data.Data() + ptr);
    ptr += sizeof(iphdr);

    return hdr;
}

udphdr Filter::ParseUDP(size_t &ptr, Buffer &data) {
    if (ptr + sizeof(udphdr) >= data.Size()) {
        throw std::runtime_error("Expected UDP");
    }
    udphdr hdr = *(udphdr*)(data.Data() + ptr);
    ptr += sizeof(udphdr);
    return hdr;
}

tcphdr Filter::ParseTCP(size_t &ptr, Buffer &data) {
    if (ptr + sizeof(tcphdr) >= data.Size()) {
        throw std::runtime_error("Expected TCP");
    }
    tcphdr hdr = *(tcphdr*)(data.Data() + ptr);
    ptr += sizeof(tcphdr);
    return hdr;
}

Filter::Filter(const char *file_path) {
    std::ifstream in(file_path, std::ios_base::in);
    if (in.fail()) {
        throw std::runtime_error(std::format("failed to open file {}", file_path));
    }

    size_t id = 0;
    while (!in.eof()) {
        std::string line;
        std::getline(in, line);
        if (line != "{") {
            continue;
        }
        
        Rule rule {
            .id_ = id++,
            .type_ = Filter::Rule::kBlack,
            .src_ip_ = 0,
            .dst_ip_ = 0,
            .src_port_ = -1,
            .dst_port_ = -1,
            .proto_ = {
                .p_proto = -1
            }
        };

        for (; std::getline(in, line);) {
            if (line == "") {
                continue;
            }

            if (line == "}") {
                break;
            }

            std::istringstream s(line);
            std::string name;
            s >> name;
            if (name == "src_ip") {
                int ip;
                s >> ip;
                rule.src_ip_ = ip;
            } else if (name == "dst_ip") {
                int ip;
                s >> ip;
                rule.dst_ip_ = ip;
            } else if (name == "src_port") {
                int port;
                s >> port;
                rule.src_port_ = port;
            } else if (name == "dst_port") {
                int port;
                s >> port;
                rule.dst_port_ = port;
            } else if (name == "protocol") {
                std::string proto;
                s >> proto;
                auto prt = getprotobyname(proto.c_str());
                if (prt == nullptr) {
                    throw std::runtime_error(std::format("Unknow protocol {}", proto));
                }
                rule.proto_ = *prt;
            } else if (name == "type") {
                std::string type;
                s >> type;
                if (type == "white") {
                    rule.type_ = rule.kWhite;
                } else if (type == "black") {
                    rule.type_ = rule.kBlack;
                } else {
                    throw std::runtime_error(std::format("Unknow type {}", type));
                }
            } else {
                throw std::runtime_error(std::format("Unknow option {}", name));
            }
        }

        rules_.push_back(rule);
    }
}

bool Filter::operator()(Buffer &buff) {
    std::cout << "------------------ Filter Log -----------------\n";
    size_t ptr = 0;

    auto eth_hdr = ParseEther(ptr, buff);
    std::cout << std::format(
        "Ether:\n\tMAC SRC: {}\n\tMAC DST: {}\n\tProto: {}\n"
      , ctomac((const char*)eth_hdr.h_source)
      , ctomac((const char*)eth_hdr.h_dest)
      , std::format("{:04x}", (short)eth_hdr.h_proto)
    );

    if (eth_hdr.h_proto == ETH_P_ARP) {
        std::cout << "Detected ARP: pass\n";
        std::cout << "-----------------------------------------------\n";
        return true;
    } else if (eth_hdr.h_proto != ETH_P_IP) {
        std::cout << std::format("Detected unknow proto ({:04x}): pass\n", (short)eth_hdr.h_proto);
        std::cout << "-----------------------------------------------\n";
        return true;
    }

    auto ip_hdr = ParseIP(ptr, buff);
    auto ip_proto = getprotobynumber(ip_hdr.protocol);

    std::cout << std::format(
        "IPv4:\n\tProtocol: {}\n\tIP SRC: {}\n\tIP DST: {}\n"
      , std::format("{} ({:x})", ip_proto ? ip_proto->p_aliases[0] : "Unknow", ip_hdr.protocol)
      , std::string(inet_ntoa(in_addr(ip_hdr.saddr)))
      , std::string(inet_ntoa(in_addr(ip_hdr.daddr)))
    );

    if (ip_proto == nullptr) {
        std::cout << std::format("Detected unknow IP proto ({:x}): pass\n", ip_hdr.protocol);
        std::cout << "-----------------------------------------------\n";
        return true;
    }

    Rule packet = {
        .src_ip_   = ip_hdr.saddr,
        .dst_ip_   = ip_hdr.daddr,
        .src_port_ = -1,
        .dst_port_ = -1,
        .proto_    = *ip_proto
    };

    if (packet.proto_.p_proto == 6 /*TCP*/) {
        auto tcp_hdr = ParseTCP(ptr, buff);
        packet.src_port_ = tcp_hdr.source;
        packet.dst_port_ = tcp_hdr.dest;

        std::cout << std::format(
            "TCP:\n\tSRC PORT: {}\n\tDSR PORT: {}\n"
          , packet.src_port_
          , packet.dst_port_
        );
    } else if (packet.proto_.p_proto == 17 /*UDP*/) {
        auto udp_hdr = ParseUDP(ptr, buff);
        packet.src_port_ = udp_hdr.source;
        packet.dst_port_ = udp_hdr.dest;

        std::cout << std::format(
            "UDP:\n\tSRC PORT: {}\n\tDSR PORT: {}\n"
          , packet.src_port_
          , packet.dst_port_
        );
    }

    for (auto& rule : rules_) {
        bool is_ok = true;
        if (rule.proto_.p_proto != -1 && rule.proto_.p_proto != packet.proto_.p_proto) {
            is_ok = false;
        }

        if (rule.src_port_ != -1 && packet.src_port_ == -1
         || rule.dst_port_ != -1 && packet.dst_port_ == -1) {
            continue; // Slip this rule
        }

        if (rule.src_ip_ != 0 && rule.src_ip_ != packet.src_ip_
         || rule.dst_ip_ != 0 && rule.dst_ip_ != packet.dst_ip_
         || rule.src_port_ != -1 && rule.src_port_ != packet.src_port_
         || rule.dst_port_ != -1 && rule.dst_port_ != packet.dst_port_) {
            is_ok = false;            
        }

        if (is_ok ^ rule.type_ == false) {
            std::cout << std::format(
                "Find block rule:\n\tID = {}\n\tSRC IP = {}\n\tDST IP = {}\n\tSRC PORT = {}\n\tDST PORT = {}\n\tPROTOCOL = {}\n\tTYPE = {}\n"
              , rule.id_
              , rule.src_ip_ == 0 ? "Any" : std::string(inet_ntoa(in_addr(rule.src_ip_)))
              , rule.dst_ip_ == 0 ? "Any" : std::string(inet_ntoa(in_addr(rule.dst_ip_)))
              , rule.src_port_ == -1 ? "Any" : std::to_string(rule.src_port_)
              , rule.dst_port_ == -1 ? "Any" : std::to_string(rule.dst_port_)
              , rule.proto_.p_proto == -1 ? "Any" : rule.proto_.p_aliases[0]
              , rule.type_ == rule.kWhite ? "WHITE" : "BLACK"
            );
            std::cout << "-----------------------------------------------\n";
            return false;
        }
    }

    std::cout << "-----------------------------------------------\n";
    return true;
}
