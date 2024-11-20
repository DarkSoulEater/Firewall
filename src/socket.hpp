#pragma once
#include <netinet/in.h>
#include "buffer.hpp"

class Socket {
  public:
    Socket(const char* intf);
    ~Socket();

    Buffer Read();
    void Write(Buffer& data);

    const char* IntfName() const { return conf_.name; }

  private:
    int fd_;
    
    struct IntfConf {
        const char* name;
        in_addr addr;
        u_long mask;
        int mtu;
        int index;  
    } conf_;

    void SetIntfConf(const char* intf);
};