#include "czkatranTestUtil.h"

//#include "/home/jianglei/czkatran/czkatran/lib/Testing/TestData/czkatranGueOptionalTestFixtures.h"
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/TestData/czkatranTPRTestFixtures.h"
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/TestData/czkatranTestFixtures.h"
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/TestData/czkatranUdpStableRtTestFixtures.h"
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/TestData/czkatranGueTestFixtures.h"

//#include "/home/cainiao/czkatran/czkatran/lib/Testing/TestData/czkatranGueOptionalTestFixtures.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/TestData/czkatranTPRTestFixtures.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/TestData/czkatranTestFixtures.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/TestData/czkatranUdpStableRtTestFixtures.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/TestData/czkatranGueTestFixtures.h"

#include "czkatranGueOptionalTestFixtures.h"
#include "czkatranTPRTestFixtures.h"
#include "czkatranTestFixtures.h"
#include "czkatranUdpStableRtTestFixtures.h"
#include "czkatranGueTestFixtures.h"
#include "czkatranTestProvision.h"
#include "czkatranTestUtil.h"
//------------------------------------2025-2-16-------------------------------
namespace czkatran {
namespace testing {

//测试外界模拟器：外界ip -----》czkatran ip ------》real ip
bool testSimulator(czkatran::czKatranLb& lb)//--------------------------√
{
    bool success {true};
    auto real = lb.getRealForFlow(czkatran::czkatranFlow{
        .src = "172.16.0.1",
        .dst = "10.200.1.1",
        .srcport = 31337,
        .dstport = 80,
        .proto = kUdp,
   });
   if(real != "10.0.0.2") {
        VLOG(2) << "real :" << real;
        LOG(INFO) << "simulation is incorrect for v4 real and v4 udp vip";
        success = false;
   }

   real = lb.getRealForFlow(czkatran::czkatranFlow{
    .src = "172.16.0.1",
    .dst = "10.200.1.1",
    .srcport = 31337,
    .dstport = 80,
    .proto = kTcp,
   });
   if(real != "10.0.0.2") {
        VLOG(2) << "real :" << real;
        LOG(INFO) << "simulation is incorrect for v4 real and v4 tcp vip";
        success = false;
   }

   real = lb.getRealForFlow(czkatran::czkatranFlow{
    .src = "172.16.0.1",
    .dst = "10.200.1.3",
    .srcport = 31337,
    .dstport = 80,
    .proto = kTcp,
   });
   if (real != "fc00::2") {
        VLOG(2) << "real: " << real;
        LOG(INFO) << "simulation is incorrect for v6 real and v4 tcp vip";
        success = false;
    }

    real = lb.getRealForFlow(czkatran::czkatranFlow{
    .src = "fc00:2::1",
    .dst = "fc00:1::1",
    .srcport = 31337,
    .dstport = 80,
    .proto = kTcp,
   });
   if(real != "fc00::3") {
        VLOG(2) << "real: " << real;
        LOG(INFO) << "simulation is incorrect for v6 real and v6 tcp vip";
        success = false;
   }

   //不存在
   real = lb.getRealForFlow(czkatran::czkatranFlow{
    .src = "fc00:2::1",
    .dst = "fc00:1::2",
    .srcport = 31337,
    .dstport = 80,
    .proto = kTcp,
   });
   if(!real.empty()) {
        VLOG(2) << "real: " << real;
        LOG(INFO) << "incorrect real for non existing vip";
        success = false;
   }

   real = lb.getRealForFlow(czkatran::czkatranFlow{
    .src = "10.0.0.1",
    .dst = "fc00:1::1",
    .srcport = 31337,
    .dstport = 80,
    .proto = kTcp,
   });
   if (!real.empty()) {
        VLOG(2) << "real: " << real;
        LOG(INFO) << "incorrect real for malformed flow #1";
        success = false;
  }

  real = lb.getRealForFlow(czkatran::czkatranFlow{
        .src = "aaaa", //非法ip
        .dst = "bbbb",
        .srcport = 31337,
        .dstport = 80,
        .proto = kTcp,
    });
    if (!real.empty()) {
        VLOG(2) << "real: " << real;
        LOG(INFO) << "incorrect real for malformed flow #2";
        success = false;
    }
    return success;
}


czkatranTestParam createDefaultTestParam(TestMode testMode)//--------------------------√
{
    czkatran::VipKey vip;
    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kTcp;
    czkatranTestParam testParam = {
        .mode = testMode,
        .testData = testMode == TestMode::GUE ? 
            czkatran::testing::gueTestFixtures
            : 
            czkatran::testing::testFixtures,
        .expectedCounters = 
        {
            {
                czkatranTestCounters::TOTAL_PKTS, 23
            },
            {
                czkatranTestCounters::LRU_MISSES, 11
            },
            {
                czkatranTestCounters::TCP_SYNS, 2
            },
            {
                czkatranTestCounters::NON_SYN_LRU_MISSES, 6
            },
            {
                czkatranTestCounters::LRU_FALLBACK_HITS, 19
            },
            {
                czkatranTestCounters::QUIC_ROUTING_WITH_CH, 7
            },
            {
                czkatranTestCounters::QUIC_ROUTING_WITH_CID, 4
            },
            {
                czkatranTestCounters::QUIC_CID_V1, 4
            },
            {
                czkatranTestCounters::QUIC_CID_V2, 2
            },
            {
                czkatranTestCounters::QUIC_CID_DROPS_REAL_0, 0
            },
            {
                czkatranTestCounters::QUIC_CID_DROPS_NO_REAL, 2
            },
            {
                czkatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0
            },
            {
                czkatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED, 0
            },
            // optional counters
            {
                czkatranTestCounters::ICMP_V4_COUNTS, 1
            },
            {
                czkatranTestCounters::ICMP_V6_COUNTS, 1
            },
            {
                czkatranTestCounters::SRC_ROUTING_PKTS_LOCAL, 2
            },
            {
                czkatranTestCounters::SRC_ROUTING_PKTS_REMOTE, 6
            },
            {
                czkatranTestCounters::INLINE_DECAP_PKTS, 4
            },
            // unused
            {
                czkatranTestCounters::TCP_SERVER_ID_ROUNTING, 0
            },
            {
                czkatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH, 0
            },
        },
        .perVipCounters = {
            {vip, std::pair<uint64_t, uint64_t>(4, 248)}
        }
    };
    return testParam;
}

czkatranTestParam createTPRTestParam()//--------------------------√
{
    czkatran::VipKey vip;
    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kTcp;
    czkatranTestParam testParam = {
        .mode = TestMode::TPR,
        .testData = czkatran::testing::tprTestFixtures,
        .expectedCounters = 
        {
            {
                czkatranTestCounters::TOTAL_PKTS, 17
            },
            {
                czkatranTestCounters::LRU_MISSES, 3
            },
            {
                czkatranTestCounters::TCP_SYNS, 1
            },
            {
                czkatranTestCounters::NON_SYN_LRU_MISSES, 2
            },
            {
                czkatranTestCounters::LRU_FALLBACK_HITS, 17
            },
            {
                czkatranTestCounters::TCP_SERVER_ID_ROUNTING, 8
            },
            {
                czkatranTestCounters::TCP_SERVER_ID_ROUTING_FALLBACK_CH, 8
            },
            {
                czkatranTestCounters::TOTAL_FAILED_BPF_CALLS, 0
            },
            {
                czkatranTestCounters::TOTAL_ADDRESS_VALIDATION_FAILED, 0
            },
        },
        .perVipCounters = {
            {
                vip, std::pair<uint64_t, uint64_t>(4, 244)
            }
        }
    };
    return testParam;
}

czkatranTestParam createUdpStableRtTestParam()//--------------------------√
{
    czkatran::VipKey vip;
    vip.address = "fc00:1::9";
    vip.port = kVipPort;
    vip.proto = kUdp;
    czkatranTestParam testParam = {
        .mode = TestMode::GUE,
        .testData = czkatran::testing::udpStableRtFixtures,
        .expectedCounters = 
        {
            {
                czkatranTestCounters::TOTAL_PKTS, 5
            },
            {
                czkatranTestCounters::STABLE_RT_CH_ROUTING, 2
            },
            {
                czkatranTestCounters::STABLE_RT_CID_ROUTING, 3
            },
            {
                czkatranTestCounters::STABLE_RT_CID_INVALID_SERVER_ID, 0
            },
            {
                czkatranTestCounters::STABLE_RT_CID_UNKNOWN_REAL_DROPPED, 0
            },
            {
                czkatranTestCounters::STABLE_RT_INVALID_PACKET_TYPE, 0
            },
        },
        .perVipCounters = {
            {
                vip, std::pair<uint64_t, uint64_t>(4, 244)
            }
        }
    };
    return testParam;
}

//------------------------------------2025-2-16-------------------------------


}
}