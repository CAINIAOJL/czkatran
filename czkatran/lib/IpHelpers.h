#pragma once




#include <folly/IPAddress.h>
#include <string>

namespace czkatran {

struct beaddr {
    union {
        uint32_t daddr;
        uint32_t v6daddr[4];
    };
    uint8_t flags;
};

class IpHelpers {

    public:
        static struct beaddr parseAddrToBe(
            const std::string& addr,
            bool Bigendian = true
        );

        static struct beaddr parseAddrToInt(const std::string& addr);

        static struct beaddr parseAddrToBe(
            const folly::IPAddress& addr,
            bool Bigendian = true
        );

        static struct beaddr parseAddrToint(const folly::IPAddress& addr);


};


}