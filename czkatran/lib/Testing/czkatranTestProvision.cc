//------------------------------------2025-2-14-------------------------------
//--------------------------√
#include "/home/jianglei/czkatran/czkatran/lib/Testing/czkatranTestProvision.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/czkatranTestProvision.h"
#include <glog/logging.h>
#include <map>
namespace czkatran {
namespace testing {

const std::string kMainInterface = "lo";
const std::string kV4TunInterface = "lo";
const std::string kV6TunInterface = "lo";
const std::string kNoExternalMap = "";
const std::vector<uint8_t> kDefalutMac = {0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF};
const std::vector<uint8_t> KLocalMac = {0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xAF};

const std::vector<std::string> kReals = {
    //ipv4
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    //ipv6
    "fc00::1",
    "fc00::2",
    "fc00::3",
};

const std::vector<::czkatran::lb_stats> kDefaultRealStats = {
    {0, 0},
    {9, 422},
    {5, 291},
    {4, 206},
    {2, 76},
    {3, 156},
};

const std::vector<::czkatran::lb_stats> kTPRRealStats = {
    {0, 0},
    {3, 181},
    {4, 244},
    {8, 356},
    {2, 134},
    {0, 0},
};

const std::map<TestMode, std::vector<::czkatran::lb_stats>> kRealsStats = {
    {TestMode::DEFAULT, kDefaultRealStats},
    {TestMode::GUE, kDefaultRealStats},
    {TestMode::TPR, kTPRRealStats}
};

void addReals(//--------------------------√
    czkatran::czKatranLb& lb,
    const czkatran::VipKey& vip,
    const std::vector<std::string>& reals //IpAddress 集合
)
{
    czkatran::NewReal real;
    real.weight = kDefaultWeight;
    for (auto& r : reals) {
        real.address = r;
        lb.addRealForVip(real, vip);
    }
}

void deleteReals(//--------------------------√
    czkatran::czKatranLb& lb,
    const czkatran::VipKey& vip,
    const std::vector<std::string>& reals //IpAddress 集合
)
{
    czkatran::NewReal real;
    real.weight = kDefaultWeight;
    for(auto& r : reals) {
        real.address = r;
        lb.deleteRealForVip(real, vip);
    }
}

void addQuicMappings(czkatran::czKatranLb& lb)//--------------------------√
{
    czkatran::QuicReal qreal;
    std::vector<czkatran::QuicReal> qreals;
    auto action = czkatran::ModifyAction::ADD;
    //6个
    std::vector<uint16_t> ids = {1022, 1023, 1025, 1024, 1026, 1027};
    for(int i = 0; i < 6; i++) {
        //CID V1
        qreal.address = kReals[i];
        qreal.id = ids[i];
        qreals.push_back(qreal);

        //CID V2
        qreal.address = kReals[i];
        constexpr uint32_t twJobMask = 0x030000;
        qreal.id = twJobMask | ids[i];
        qreals.push_back(qreal);

        LOG(INFO) << "Adding mapping for" << qreal.address << " with id = " << qreal.id;

        printf("%02X%02X%02X%02X\n",
                (qreal.id >> 24) & 0xFF,
                (qreal.id >> 16) & 0xFF,
                (qreal.id >> 8) & 0xFF,
                (qreal.id & 0xFF)); 
    }
    lb.modifyQuicRealsMapping(action, qreals);
}

void prepareLbData(czkatran::czKatranLb& lb)//--------------------------√
{
    lb.restartczKatranMonitor(kMonitorLimit);
    czkatran::VipKey vip;
    //服务器端节点
    //一个vip对应一组reals
    std::vector<std::string> reals = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
    std::vector<std::string> reals6 = {"fc00::1", "fc00::2", "fc00::3"};

    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kUdp;

//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kUdp]---------//
    lb.addVip(vip);
    addReals(lb, vip, reals); //vip: udp >> reals
//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kUdp]---------//

//-------vip(Tcp)[address: 10.200.1.1, port: kVipPort, proto: kTcp]---------//
    vip.proto = kTcp;
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(Tcp)[address: 10.200.1.1, port: kVipPort, proto: kTcp]---------//

//-------vip(Tcp)[address: 10.200.1.2, port: 0, proto: kTcp]---------//
    vip.address = "10.200.1.2";
    vip.port = 0;
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(Tcp)[address: 10.200.1.2, port: 0, proto: kTcp]---------//

//-------vip(Tcp)[address: 10.200.1.4, port: 0, proto: kTcp]---------//
    vip.address = "10.200.1.4";
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(Tcp)[address: 10.200.1.4, port: 0, proto: kTcp]---------//

//------------------------------------2025-2-14-------------------------------

//------------------------------------2025-2-15-------------------------------
 
    lb.modifyVip(vip, kDportHash);
//-------vip(Tcp)[address: 10.200.1.3, port: kVipPort, proto: kTcp]---------//   
    vip.address = "10.200.1.3";
    vip.port = kVipPort;
    lb.addVip(vip);
    addReals(lb, vip, reals6);
//-------vip(Tcp)[address: 10.200.1.3, port: kVipPort, proto: kTcp]---------//   
    
//-------vip(Tcp)[address: fc00:1::1, port: kVipPort, proto: kTcp]---------// 
    vip.address = "fc00:1::1";
    lb.addVip(vip);
    addReals(lb, vip, reals6);
//-------vip(Tcp)[address: fc00:1::1, port: kVipPort, proto: kTcp]---------// 
    
    addQuicMappings(lb);
//-------vip(Quic)[address: 10.200.1.5, port: 443, proto: kUdp]---------// 
    vip.address = "10.200.1.5";
    vip.proto = kUdp;
    vip.port = 443;
    lb.addVip(vip);
    lb.modifyVip(vip, kQuicVip);
    addReals(lb, vip, reals);
//-------vip(Quic)[address: fc00:1::2, port: 443, proto: kUdp]---------// 

    vip.address = "fc00:1::2";
    lb.addVip(vip);
    lb.modifyVip(vip, kQuicVip);
    addReals(lb, vip, reals6);
//-------vip(Quic)[address: fc00:1::2, port: 443, proto: kUdp]---------// 

    lb.addHealthcheckerDst(1, "10.0.0.1");
    lb.addHealthcheckerDst(2, "10.0.0.2");
    lb.addHealthcheckerDst(3, "fc00::1");
}

void prepareLbDataStableRt(czkatran::czKatranLb& lb)//--------------------------√
{
    lb.restartczKatranMonitor(kMonitorLimit);
    czkatran::VipKey vip;

    std::vector<std::string> reals = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
    std::vector<std::string> reals6 = {"fc00::1", "fc00::2", "fc00::3"};

    vip.address = "fc00:1::9";
    vip.proto = kUdp;
    vip.port = kVipPort;
    lb.addVip(vip);
    addReals(lb, vip, reals6);
    lb.modifyVip(vip, kUdpStableRouting);

    //ipv4 vip
    vip.address = "10.200.1.90";
    lb.addVip(vip);
    addReals(lb, vip, reals);
    lb.modifyVip(vip, kUdpStableRouting);

    //ipv4 vip ignores dst_port for Tunnel services
    vip.address = "10.200.1.2";
    vip.port = 0;
    lb.addVip(vip);
    addReals(lb, vip, reals);

    vip.address = "10.200.1.4";
    lb.addVip(vip);
    addReals(lb, vip, reals);
    lb.modifyVip(vip, kDportHash);

    //ipv4 in ipv6
    vip.address = "10.200.1.3";
    vip.port = kVipPort;
    lb.addVip(vip);
    addReals(lb, vip, reals6);

    //ipv6 in ipv6
    vip.address = "fc00:1::1";
    lb.addVip(vip);
    addReals(lb, vip, reals6);

    //测试quic协议
    addQuicMappings(lb);

    //ipv4 vip
    vip.proto = kUdp;
    vip.port = 443;
    vip.address = "10.200.1.5";
    lb.addVip(vip);
    lb.modifyVip(vip, kQuicVip);
    addReals(lb, vip, reals);

    //ipv6 vip
    vip.address = "fc00:1::2";
    lb.addVip(vip);
    lb.modifyVip(vip, kQuicVip);
    addReals(lb, vip, reals6);

    lb.addHealthcheckerDst(1, "10.0.0.1");
    lb.addHealthcheckerDst(2, "10.0.0.2");
    lb.addHealthcheckerDst(3, "fc00::1");
}

void prepareOptionalLbData(czkatran::czKatranLb& lb)//--------------------------√
{
    czkatran::VipKey vip;

    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kUdp;
    lb.modifyVip(vip, kSrcRouting); //源地址路由选项

    vip.address = "fc00:1::1";
    vip.proto = kTcp;
    lb.modifyVip(vip, kSrcRouting);

    lb.addSrcRoutingRule({"192.168.0.0/17"}, "fc00::2307:1");
    lb.addSrcRoutingRule({"192.168.100.0/24"}, "fc00::2307:2");
    lb.addSrcRoutingRule({"fc00:2307::/32"}, "fc00::2307:3");
    lb.addSrcRoutingRule({"fc00:2307::/64"}, "fc00::2307:4");
    lb.addSrcRoutingRule({"fc00:2::/64"}, "fc00::2307:10");
    lb.addInlineDecapDst("fc00:1404::1");

    vip.address = "10.200.1.6";
    vip.port = kVipPort;
    vip.proto = kUdp;
    lb.addVip(vip);
    lb.modifyVip(vip, kLocalVip);
    addReals(lb, vip, {"10.0.0.6"});
    lb.modifyReal("10.0.0.6", kLocalReal);
}

void prepareVipUnintializedLbData(czkatran::czKatranLb& lb)//--------------------------√
{
    czkatran::VipKey vip;
    vip.address = "10.200.1.99";
    vip.proto = kTcp;
    vip.port = kVipPort;
    lb.addVip(vip);
    
    vip.address = "fc00:1::11";
    vip.proto = kUdp;
    lb.addVip(vip);
}

void preparePerfTestingLbData(czkatran::czKatranLb& lb)//--------------------------√
{
    for(auto& dst : kReals) {
        lb.addInlineDecapDst(dst);
    }   
}

const std::vector<::czkatran::lb_stats> czkatranTestParam::
expectedRealStats() noexcept//--------------------------√
{
    auto it = kRealsStats.find(mode);
    CHECK(it != kRealsStats.end());
    return it->second;
}

uint64_t czkatranTestParam:: expectedTotalPktsForVip(
    const czkatran::VipKey& vip) noexcept//--------------------------√

{
    if(perVipCounters.count(vip) == 0) {
        LOG(WARNING) << fmt::format(
            "perVipCounters does not contain vip: IPAddress {}, port {}, proto {}",
            vip.address, vip.port, vip.proto
        );
        return 0;
    }
    return perVipCounters[vip].first;
}

uint64_t czkatranTestParam:: expectedTotalBytesForVip(
    const czkatran::VipKey& vip) noexcept//--------------------------√
{
    if(perVipCounters.count(vip) == 0) {
        LOG(WARNING) << fmt::format(
            "perVipCounters does not contain vip: IPAddress {}, port {}, proto {}",
            vip.address, vip.port, vip.proto
        );
        return 0;
    }
    return perVipCounters[vip].second;
}

uint64_t czkatranTestParam:: _lookup_counter(czkatranTestCounters counter) noexcept { //--------------------------√
    if(expectedCounters.count(counter) == 0) {
        LOG(WARNING) << "expectedCounters does not contain counter: " << int(counter);
        return 0;
    }
    return expectedCounters[counter];
}

uint64_t czkatranTestParam:: expectedTotalPkts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TOTAL_PKTS);
  }
uint64_t czkatranTestParam:: expectedTotalLruMisses() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::LRU_MISSES);
}
uint64_t czkatranTestParam:: expectedTotalTcpSyns() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TCP_SYNS);
}
uint64_t czkatranTestParam:: expectedTotalTcpNonSynLruMisses() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::NON_SYN_LRU_MISSES);
}
uint64_t czkatranTestParam:: expectedTotalLruFallbackHits() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::LRU_FALLBACK_HITS);
}
uint64_t czkatranTestParam:: expectedQuicRoutingWithCh() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_ROUTING_WITH_CH);
}
uint64_t czkatranTestParam:: expectedQuicRoutingWithCid() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_ROUTING_WITH_CID);
}
uint64_t czkatranTestParam:: expectedQuicCidV1Counts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_CID_V1);
}
uint64_t czkatranTestParam:: expectedQuicCidV2Counts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_CID_V2);
}
uint64_t czkatranTestParam:: expectedQuicCidDropsReal0Counts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_CID_DROPS_REAL_0);
}
uint64_t czkatranTestParam:: expectedQuicCidDropsNoRealCounts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::QUIC_CID_DROPS_NO_REAL);
}
uint64_t czkatranTestParam:: expectedTcpServerIdRoutingCounts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TCP_SERVER_ID_ROUNTING);
}
uint64_t czkatranTestParam:: expectedTcpServerIdRoutingFallbackCounts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH);
}
uint64_t czkatranTestParam:: expectedUdpStableRoutingWithCh() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::STABLE_RT_CH_ROUTING);
}
uint64_t czkatranTestParam:: expectedUdpStableRoutingWithCid() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::STABLE_RT_CID_ROUTING);
}
uint64_t czkatranTestParam:: expectedUdpStableRoutingInvalidSid() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::STABLE_RT_CID_INVALID_SERVER_ID);
}
uint64_t czkatranTestParam:: expectedUdpStableRoutingUnknownReals() noexcept { //--------------------------√
    return _lookup_counter(
        czkatranTestCounters::STABLE_RT_CID_UNKNOWN_REAL_DROPPED);
}
uint64_t czkatranTestParam:: expectedUdpStableRoutingInvalidPacketType() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::STABLE_RT_INVALID_PACKET_TYPE);
}
uint64_t czkatranTestParam:: expectedTotalFailedBpfCalls() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TOTAL_FAILED_BPF_CALLS);
}
uint64_t czkatranTestParam:: expectedTotalAddressValidations() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED);
}
uint64_t czkatranTestParam:: expectedIcmpV4Counts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::ICMP_V4_COUNTS);
}
uint64_t czkatranTestParam:: expectedIcmpV6Counts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::ICMP_V6_COUNTS);
}
uint64_t czkatranTestParam:: expectedSrcRoutingPktsLocal() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::SRC_ROUTING_PKTS_LOCAL);
}
uint64_t czkatranTestParam:: expectedSrcRoutingPktsRemote() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::SRC_ROUTING_PKTS_REMOTE);
}
uint64_t czkatranTestParam:: expectedInlineDecapPkts() noexcept { //--------------------------√
    return _lookup_counter(czkatranTestCounters::INLINE_DECAP_PKTS);
}
  



}
}