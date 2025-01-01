#pragma once

#include <string>

namespace czkatran {
namespace {
    int CZKDefaultPos = 8;
    std::string CZKDefaultMapPath = "";
    std::string CZKDefaultInterface = "lo";
}





/**
 * @param decap_v4 number of IPv4 packets decapsulated
 * @param decap_v6 number of IPv6 packets decapsulated
 * @param total number of packets decapsulated
 */
struct decap_stats {
    __uint64_t decap_v4;
    __uint64_t decap_v6;
    __uint64_t total;
    __uint64_t tpr_misrouted;
    __uint64_t tpr_total;
};

/**
 * @param string progpath ---path to the XDP program
 * @param string mappath ---path to the BPF map file
 * @param int progPos ---path to bpf prog array
 * @param string interface ---the interface to attach XDP program to
 * @param bool defaultNoExit ---should remove XDP prog from kernel on exit
 */
struct XdpDecapConfig {
    std::string progPath;
    std::string mapPath = CZKDefaultMapPath;
    int progPos = CZKDefaultPos;
    std::string interface = CZKDefaultInterface;
    bool defaultNoExit = true;
};



}