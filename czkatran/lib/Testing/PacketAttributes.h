#pragma once

#include <string>
#include <folly/Optional.h>

namespace czkatran {

struct PacketAttributes {    
    //Base_64 encoded value of the packet sent to czkatran
    std::string inputPacket;

    //Human-readable description of the packet being sent
    std::string description;

    //Expected return value of the balancer bpf program. Example: "XDP_TX"
    std::string expectedReturnValue;
    
    //base-64 encoded value of the expected packet after passing
    //the input packet through czkatran
    std::string expectedOutputPacket;

    // We set this if we want to verify whether or not the packet was
    // routed through global lru
    std::optional<bool> routeThroughGlobalLru {std::nullopt};
};

}