#include "IpHelpers.h"

#include <folly/lang/Bits.h>
#include <stdexcept>

namespace czkatran {

constexpr int Uint32_bytes = 4;
constexpr uint8_t V6DADDR = 1;

struct beaddr IpHelpers:: parseAddrToBe(
            const std::string& addr,
            bool Bigendian
        )
{
    return parseAddrToBe(folly::IPAddress(addr), Bigendian);

}

struct beaddr IpHelpers:: parseAddrToBe(
            const folly::IPAddress& addr,
            bool Bigendian
        )
{
    struct beaddr be_addr = {};
    if(addr.isV4()) {
        //是否是ipv4地址
        be_addr.flags = 0;
        if(Bigendian) {
            be_addr.daddr = addr.asV4().toLong();
        } else {
            be_addr.daddr = addr.asV4().toLongHBO();
        }
    } else {
        for(int postion = 0; postion < 4; postion++) {
            uint32_t addr_part = *(uint32_t*)(addr.bytes() + Uint32_bytes * postion);
            if(Bigendian) {
                be_addr.v6daddr[postion] = addr_part;
            } else {
                be_addr.v6daddr[postion] = folly::Endian::big(addr_part);
            }
        }
        be_addr.flags = V6DADDR;
    }
    return be_addr;
}

struct beaddr IpHelpers:: parseAddrToInt(const std::string& addr) {
    return parseAddrToBe(addr, false);
}


struct beaddr IpHelpers:: parseAddrToint(const folly::IPAddress& addr) {
    return parseAddrToBe(addr, false);
}





}