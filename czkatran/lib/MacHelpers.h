#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace czkatran {

    std::vector<uint8_t> convertMacToUint(const std::string& macAddress);
    std::string convertMacToString(const std::vector<uint8_t>& macAddress);




}