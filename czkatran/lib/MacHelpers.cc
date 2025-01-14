#include "MacHelpers.h"
#include <glog/logging.h>
#include <folly/MacAddress.h>

namespace czkatran
{
    
std::vector<uint8_t> convertMacToUint(const std::string& macAddress) {
    std::vector<uint8_t> mac(6);
    folly::MacAddress default_mac;

    try {
        default_mac.parse(macAddress);
    } catch (const std::exception& e) {
        LOG(ERROR) << "Exception while parsing mac address: " << e.what() << std::endl;
        return mac;
    }

    auto mac_bytes = default_mac.bytes();
    for(int i = 0; i < 6; i++) {
        mac[i] = mac_bytes[i];
    }
    return mac;
}

//mac 48位
std::string convertMacToString(const std::vector<uint8_t>& macAddress) {
    if(macAddress.size() != 6) {
        return "Unkonwn Mac Address !";
    }
    uint16_t mac_part;
    std::string mac_part_str;
    std::string mac_str;

    for(auto m : macAddress) {
        mac_part = m;
        mac_part_str = fmt::format("{0:02x}:", mac_part);
        mac_str += mac_part_str;
    }
    return mac_str;
}









} // namespace czkatran










