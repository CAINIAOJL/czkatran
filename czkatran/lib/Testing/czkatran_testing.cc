//------------------------------------2025-2-14-------------------------------
//--------------------------√
#include <chrono> //时间
#include <iostream>
#include <thread>


#include <folly/Conv.h>
#include <folly/File.h>
#include <folly/FileUtil.h>
#include <folly/Range.h>
#include <gflags/gflags.h>

#include "MonitoringStructs.h"
#include "czkatranLbStructs.h"
#include "BpfTester.h"

#include "czkatranGueOptionalTestFixtures.h"
#include "czkatranHCTestFixtures.h"
#include "czkatranOptionalTestFixtures.h"
#include "czkatranTestProvision.h"
#include "czkatranTestUtil.h"
#include "czkatranUdpStableRtTestFixtures.h"

using namespace czkatran::testing;
using czkatranFeatureEnum = czkatran::czkatranFeatureEnum;

#ifndef MAX_VIPS
#define MAX_VIPS 512
#endif

DEFINE_string(pcap_input, "", "path to input pcap file1");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(monitor_output, "", "path to output monitor file");

DEFINE_string(balancer_prog, "balancer.o", "path to balancer prog");
DEFINE_string(reloaded_balancer_prog, "", "path to balancer bpf prog which would reload main one");
DEFINE_string(healthchecking_prog, "healthchecking.o", "path to healthchecking prog");

DEFINE_bool(print_base64, false, "print packets in base64");
DEFINE_bool(test_from_fixturesm, false, "run tests on predefined dataset");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_bool(optional_tests, false, "run optional tests");
DEFINE_bool(optional_counter_tests, false, "run optional counter tests");
DEFINE_bool(gue, false, "run GUE tests instead of IPIP ones");
DEFINE_bool(stable_rt, false, "run UDP stable routing tests");
DEFINE_bool(tpr, false, "run TPR tests (TCP Server_Id based routing) instead of IPIP or GUE tests");

DEFINE_int32(repeat, 1000000, "perf test runs for single packet");
DEFINE_int32(position, -1, "perf test runs for single packet");
DEFINE_bool(iobuf_storage, false, "test iobuf storage for czkatran monitoring");
DEFINE_int32(packet_num, -1, "Pass packet number to run single test, default -1 to run all");

DEFINE_int32(install_features_mask, 0, "Bitmask of katran features to install. 1 = SrcRouting, 2 = InlineDecap, "
    "4 = Introspection, 8 = GueEncap, 16 = DirectHealthchecking, "
    "32 = LocalDeliveryOptimization. "
    "e.g. 13 means SrcRouting + Introspection + GueEncap");
DEFINE_int32(remove_features_mask,0,"Bitmask of katran features to install. 1 = SrcRouting, 2 = InlineDecap, "
    "4 = Introspection, 8 = GueEncap, 16 = DirectHealthchecking, "
    "32 = LocalDeliveryOptimization. "
    "e.g. 13 means SrcRouting + Introspection + GueEncap");

//------------------------------------2025-2-17/9-------------------------------
void validateMapSize(//--------------------------√
    czkatran::czKatranLb& lb,
    const std::string& map_name,
    int expected_current,
    int expected_max
)
{
    auto map_stats = lb.getBpfMapStats(map_name);
    VLOG(3) << fmt::format(
        "map_name: {} : current_entries: {} max_entries: {}",
        map_name,
        map_stats.currentEntries,
        map_stats.maxEntries
    );
    if(expected_current != map_stats.currentEntries) {
        LOG(INFO) << fmt::format(
            "map_name: {} : current_entries: {} Expected_Current_entries: {}",
            map_name,
            map_stats.currentEntries,
            expected_current
        );
    }

    if(expected_max != map_stats.maxEntries) {
        LOG(INFO) << fmt::format(
            "map_name: {} : max_entries: {} Expected_max_entries: {}",
            map_name,
            map_stats.maxEntries,
            expected_max
        );
    }
}


void preTestOptionalLbCounters(czkatran::czKatranLb& lb)//--------------------------√
{
    validateMapSize(lb, "vip_map", 0, czkatran::kDefaultMaxVips);
    validateMapSize(lb, "reals", czkatran::kDefaultMaxReals, czkatran::kDefaultMaxReals);
    if(!FLAGS_healthchecking_prog.empty()) {
        validateMapSize(lb, "hc_reals_map", 0, czkatran::kDefaultMaxReals);
    }
    LOG(INFO) << "initial testing of counters is complete";
    return;
}

void testLbCounters(czkatran::czKatranLb& lb, czkatranTestParam& testParam)//--------------------------√
{
    czkatran::VipKey vip;
    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kTcp;
    LOG(INFO) << "Testing counters's sanity, Printing on errors only";
    for(auto& vipcounter : testParam.perVipCounters) {
        auto vipstats = lb.getStatsForVip(vip);
        if((vipstats.v1 != testParam.expectedTotalPktsForVip(vipcounter.first)) || 
            (vipstats.v2 != testParam.expectedTotalBytesForVip(vipcounter.first))) {
            LOG(ERROR) << fmt::format(
                "pckt: {}, bytes: {} is incorrect for vip: address {}, port {}, proto {}",
                vipstats.v1,
                vipstats.v2,
                vip.address,
                vip.port,
                vip.proto
            );
        }
    }

    auto stats = lb.getLruStats();
    if((stats.v1 != testParam.expectedTotalPkts()) || 
        stats.v2 != testParam.expectedTotalLruMisses()) {
        LOG(ERROR) << fmt::format(
            "Total pckt: {}, misses: {} is incorrect for lru",
            stats.v1,
            stats.v2
        );
    }

    stats = lb.getLruMissStats();
    if((stats.v1 != testParam.expectedTotalTcpSyns())||
        (stats.v2 != testParam.expectedTotalTcpNonSynLruMisses())) {
        LOG(ERROR) << fmt::format(
            "Tcp syns: {}, Tcp non-syns: {} is incorrect for lru",
            stats.v1,
            stats.v2
        );
    }

    stats = lb.getLruFallbackStats();
    if((stats.v1 != testParam.expectedTotalLruFallbackHits())) {
        LOG(ERROR) << fmt::format(
            "Fallback hits: {} is incorrect for lru",
            stats.v1
        );
    }

    auto tprstats = lb.getTcpServerIdRoutingStats();
    if((tprstats.sid_routed != testParam.expectedTcpServerIdRoutingCounts()) || 
        tprstats.ch_routed != testParam.expectedTcpServerIdRoutingFallbackCounts())
    {
        LOG(ERROR) << fmt::format(
            "Counters for Tcp server-id routing with CH(v1) : {}",
                ", with server-id (v2) : {}",
                "Counters for TCP server-id based routing are incorrect",
                tprstats.ch_routed,
                tprstats.sid_routed
        );
    }

    auto quicstats = lb.getLbQuicPacketsStats();
    if(quicstats.ch_routed != testParam.expectedQuicRoutingWithCh() || 
        quicstats.cid_routed != testParam.expectedQuicRoutingWithCid()) 
    {
        LOG(ERROR) << fmt::format(
            "Counters for Quic routing with CH: {}",
            ", with connection-id: {}, are incorrect",
            quicstats.ch_routed,
            quicstats.cid_routed
        );
    }

    if(quicstats.cid_v1 != testParam.expectedQuicCidV1Counts() ||
        quicstats.cid_v2 != testParam.expectedQuicCidV2Counts())
    {
        LOG(ERROR) << fmt::format(
            "Counters for Quic routing with CID: {}",
            ", with connection-id: {} are incorrect",
            quicstats.cid_v1,
            quicstats.cid_v2
        );
    }

    if(quicstats.cid_invalid_server_id != testParam.expectedQuicCidDropsReal0Counts() ||
        quicstats.cid_unknown_real_dropped != testParam.expectedQuicCidDropsNoRealCounts())
    {
        LOG(ERROR) << fmt::format(
            "QUIC CID drop counters v1: {}",
            ", v2: {} are incorrect",
            quicstats.cid_invalid_server_id,
            quicstats.cid_unknown_real_dropped
        );
    }

    auto realstats = testParam.expectedRealStats();
    for(int i = 0; i < realstats.size(); i++) {
        auto real = kReals[i];
        auto id = lb.getIndexForReal(real);
        if(id < 0) {
            LOG(INFO) << fmt::format(
                "Real: {} is not found in the LB",
                real
            );
        }
        stats = lb.getRealStats(id);
        auto expected_stats = realstats[i];
        if((stats.v1 != expected_stats.v1) || (stats.v2 != expected_stats.v2)) {
            VLOG(2)<< fmt::format(
                "stats for real: {} v1: {}, v2: {} are incorrect",
                real,
                stats.v1,
                stats.v2
            );
        }
    }
    auto lb_stats = lb.getczKatranLbStats();
    if(lb_stats.bpfFailedCalls != testParam.expectedTotalFailedBpfCalls()) {
        VLOG(2) << fmt::format(
            "Total failed bpf calls: {} is incorrect",
            lb_stats.bpfFailedCalls
        );
    }
    if(lb_stats.addrValidationFailed != testParam.expectedTotalAddressValidations()) {
        VLOG(2) << fmt::format(
            "Total address validations: {} is incorrect",
            lb_stats.addrValidationFailed
        );
    }
    LOG(INFO) << "Testing counters is complete";
    return;
}

void postTestOptionalLbCounters(czkatran::czKatranLb& lb)//--------------------------√
{
    validateMapSize(lb, "vip_map", 8, czkatran::kDefaultMaxVips);
    validateMapSize(lb, "reals", czkatran::kDefaultMaxReals, czkatran::kDefaultMaxReals);
    if(!FLAGS_healthchecking_prog.empty()) {
        validateMapSize(lb, "hc_reals_map", 3, czkatran::kDefaultMaxReals);
    }
    LOG(INFO) << "Followup testing of counters is complete";
}

void testczkatranSimulator(czkatran::czKatranLb& lb)//--------------------------√
{
    lb.stopKatranMonitor();
    //这个线程睡眠一秒钟
    std::this_thread::sleep_for(std::chrono::seconds(1));
    constexpr std::array<czkatran::monitoring::EventId, 2> events = {
        czkatran::monitoring::EventId::TCP_NONSYN_LRUMISS,
        czkatran::monitoring::EventId::PACKET_TOOBIG
    };

    for(const auto event : events) {
        auto buf = lb.getczKatranMonitorEventBuffer(event);
        std::string fname;
        folly::toAppend(FLAGS_monitor_output, "_event_", event, &fname);
        auto pcap_file = folly::File(fname.c_str(), O_RDWR | O_CREAT | O_TRUNC);
        auto res = folly::writeFull(pcap_file.fd(), buf->data(), buf->length());
        if(res < 0) {   
            LOG(ERROR) << "Failed to write pcap file";
        }
    }
}

void testHcFromFixtrue(czkatran::czKatranLb& lb, czkatran::BpfTester& tester)//--------------------------√
{   
    int prog_fd = lb.getHealthcheckerprogFd();
    if(prog_fd < 0) {
        LOG(INFO) << "Healthchecker prog is not loaded";
    }
    tester.resetTestFixtures(czkatran::testing::hcTestFixtures);
    auto ctxs = czkatran::testing::getInputCtxsForHcTest();
    tester.testClsFromFixture(prog_fd, ctxs);
}

void testOptionalLbCounters(czkatran::czKatranLb& lb, czkatranTestParam& testParam)//--------------------------√
{
    LOG(INFO) << "Testing optional counters's sanity";
    auto stats = lb.getIcmpTooBigStats();
    if((stats.v1 != testParam.expectedIcmpV4Counts()) || 
        stats.v2 != testParam.expectedIcmpV6Counts())
    {
        LOG(INFO) << fmt::format(
            "ICMP too big counters v4: {}, v6: {} are incorrect",
            stats.v1,
            stats.v2
        );
    }
    stats = lb.getSrcRoutingStats();
    if((stats.v1 != testParam.expectedSrcRoutingPktsLocal()) || 
        stats.v2 != testParam.expectedSrcRoutingPktsRemote())
    {
        LOG(INFO) << fmt::format(
            "Src routing counters v4: {}, v6: {} are incorrect",
            stats.v1,
            stats.v2
        );
    }
    stats = lb.getInlineDecapStats();
    if(stats.v1 != testParam.expectedInlineDecapPkts()) {
        LOG(INFO) << fmt::format(
            "Inline decap counters v4: {} are incorrect",
            stats.v1
        );
    }
    LOG(INFO) << "czKatranMonitor stats (only for -DKATRAN_INTROSPECTION)";
    auto mmonitor_stats = lb.getKatranMonitorStats();
    LOG(INFO) << fmt::format(
        "czKatranMonitor stats: limit {}, amount {}, are incorrect",
        mmonitor_stats.limit,
        mmonitor_stats.amount
    );
    LOG(INFO) << "Testing optional counters is complete";
}

void testStableRtLbCounters(czkatran::czKatranLb& lb, czkatranTestParam& testParam)//--------------------------√
{
    LOG(INFO) << "Testing stable rt lb counters's sanity";
    auto stats = lb.getUdpStableRoutingStats();
    if(stats.ch_routed != testParam.expectedUdpStableRoutingWithCh()) {
        LOG(ERROR) << fmt::format(
            "UDP stable routing counters with CH: {} are incorrect",
            stats.ch_routed
        );
    }
    if(stats.cid_routed != testParam.expectedUdpStableRoutingWithCid()) {
        LOG(ERROR) << fmt::format(
            "UDP stable routing counters with CID: {} are incorrect",
            stats.cid_routed
        );
    }
    if(stats.cid_invalid_server_id != testParam.expectedUdpStableRoutingInvalidSid()) {
        LOG(ERROR) << fmt::format(
            "UDP stable routing counters with CID: {} are incorrect",
            stats.cid_invalid_server_id
        );
    }
    if(stats.cid_unknown_real_dropped != testParam.expectedUdpStableRoutingUnknownReals()) {
        LOG(ERROR) << fmt::format(
            "UDP stable routing counters with CID: {} are incorrect",
            stats.cid_unknown_real_dropped
        );
    }
    if(stats.invalid_packet_type != testParam.expectedUdpStableRoutingInvalidPacketType()) {
        LOG(ERROR) << fmt::format(
            "UDP stable routing counters with CID: {} are incorrect",
            stats.invalid_packet_type
        );
    }
    LOG(INFO) << "UDP stable routing counters are complete";
}

void runTestFromFixtures(//--------------------------√
    czkatran::czKatranLb& lb,
    czkatran::BpfTester& tester,
    czkatranTestParam& testParam
)
{
    prepareLbData(lb);
    prepareVipUnintializedLbData(lb);

    tester.resetTestFixtures(testParam.testData);
    auto prog_fd = lb.getczKatranProgFd();
    tester.setBpfProgFd(prog_fd);
    tester.testFromFixture();
    testLbCounters(lb, testParam);
    if(FLAGS_optional_counter_tests) {
        postTestOptionalLbCounters(lb);
    }
    testSimulator(lb);
    if(FLAGS_iobuf_storage) {
        LOG(INFO) << "Test czkatran monitor";
        testczkatranSimulator(lb);
    }
    testHcFromFixtrue(lb, tester);
    if(FLAGS_optional_tests) {
        prepareOptionalLbData(lb);
        if(FLAGS_gue) {
            tester.resetTestFixtures(czkatran::testing::gueOptionalTestFixtures);
        } else {
            tester.resetTestFixtures(czkatran::testing::optionalTestFixtures);
        }
        tester.testFromFixture();
        testOptionalLbCounters(lb, testParam);
    }
    if(FLAGS_stable_rt) {
        prepareLbDataStableRt(lb);
        tester.resetTestFixtures(czkatran::testing::udpStableRtFixtures);
        tester.testFromFixture();
        auto udpTestParam = createUdpStableRtTestParam();
        testStableRtLbCounters(lb, udpTestParam);
    }
}

static const std::vector<czkatranFeatureEnum> kAllfeatures = {//--------------------------√
    czkatranFeatureEnum::DirectHealthchecking,
    czkatranFeatureEnum::SrcRouting,
    czkatranFeatureEnum::InlineDecap,
    czkatranFeatureEnum::Introspection,
    czkatranFeatureEnum::GueEncap,
    czkatranFeatureEnum::DirectHealthchecking,
    czkatranFeatureEnum::LocalDeliveryOptimization,
    czkatranFeatureEnum::FlowDebug,
};

std::string toString(czkatranFeatureEnum feature) {//--------------------------√
    switch (feature)
    {
    case czkatranFeatureEnum::SrcRouting :
        return "SrcRouting";
        break;
    case czkatranFeatureEnum::InlineDecap :
        return "InlineDecap";
        break;
    case czkatranFeatureEnum::Introspection :
        return "Introspection";
        break;
    case czkatranFeatureEnum::GueEncap :
        return "GueEncap";
        break;
    case czkatranFeatureEnum::LocalDeliveryOptimization :
        return "LocalDeliveryOptimization";
        break;
    case czkatranFeatureEnum::FlowDebug :
        return "FlowDebug";
        break;
    case czkatranFeatureEnum::DirectHealthchecking : 
        return "DirectHealthchecking";
        break;
    default:
        return "UNKNOWN";
        break;
    }
    folly::assume_unreachable();
}

void listFeatures(czkatran::czKatranLb& lb)//--------------------------√
{
    for(auto feature : kAllfeatures) {
        if(lb.hasFeature(feature)) {
            LOG(INFO) << fmt::format("Feature {} is enabled", toString(feature));
        }
    }
}


void testInstallAndRemoveFeatures(czkatran::czKatranLb& lb)//--------------------------√
{
    if(FLAGS_install_features_mask > 0) {
        for(auto feature : kAllfeatures) {
            if(FLAGS_install_features_mask & static_cast<int>(feature)) {
                if(lb.installFeature(feature, FLAGS_reloaded_balancer_prog)) {
                    LOG(INFO) << fmt::format("Feature {} is installed", toString(feature));
                } else {
                    LOG(ERROR) << fmt::format("Feature {} is not installed", toString(feature));
                }
            }
        }
    }

    if(FLAGS_remove_features_mask > 0) {
        for(auto feature : kAllfeatures) {
            if(FLAGS_remove_features_mask & static_cast<int>(feature)) {
                if(lb.removeFeature(feature, FLAGS_reloaded_balancer_prog)) {
                    LOG(INFO) << fmt::format("Feature {} is removed", toString(feature));
                } else {
                    LOG(ERROR) << fmt::format("Feature {} is not removed", toString(feature));
                }
            }
        }
    }
}


//------------------------------------2025-2-17/9-------------------------------
czkatranTestParam getTestParam() {//--------------------------√
    if(FLAGS_gue) {
        return createDefaultTestParam(TestMode::GUE);
    } else if(FLAGS_tpr) {
        return createTPRTestParam();
    } else {
        return createDefaultTestParam(TestMode::DEFAULT);
    }
}
//------------------------------------2025-2-15-------------------------------
    

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;
    czkatran::TesterConfig config;
    auto testParam = getTestParam();
//------------------------------------2025-2-14------------------------------- 

//------------------------------------2025-2-16-------------------------------

    config.inputFileName = FLAGS_pcap_input;
    config.outputFileName = FLAGS_pcap_output;
    config.testData = testParam.testData;

    if(FLAGS_packet_num >= 0) {
        config.singleTestRunPacketNumber_ = FLAGS_packet_num;
    }
    czkatran::BpfTester tester(config);
    if(FLAGS_print_base64) {
        if(FLAGS_pcap_input.empty()) {
            std::cout << "The path of pcap_input file is empty";
            return 1;
        }
        tester.printPktsBase64();
        return 0;
    }

    czkatran::czKatranMonitorConfig czkmconfig;
    czkmconfig.path = FLAGS_monitor_output;
    if(FLAGS_iobuf_storage) {
        czkmconfig.storage = czkatran::PcapStorageFormat::IOBUF;
        czkmconfig.bufferSize = k1Mbyte;
    }

    czkatran::czKatranConfig kconfig {
        kMainInterface,
        kV4TunInterface,
        kV6TunInterface,
        FLAGS_balancer_prog,
        FLAGS_healthchecking_prog,
        kDefaultMac,
        kDefaultPriority,
        kNoExternalMap,
        kDefaultKatranPos
    };

    kconfig.enableHc = FLAGS_healthchecking_prog.empty() ? false : true;
    kconfig.monitorConfig = czkmconfig;
    kconfig.katranSrcV4 = "10.0.13.37";
    kconfig.katranSrcV6 = "fc00:2307::1337";
    kconfig.localMac = kLocalMac;
    kconfig.maxVips = MAX_VIPS;

    auto lb = std::make_unique<czkatran::czKatranLb>
                    (kconfig, std::make_unique<czkatran::BpfAdapter>(kconfig.memlockUnlimited));

    lb->loadBpfProgs();
    listFeatures(*lb);
    auto balancer_prog_fd = lb->getczKatranProgFd();
    if(FLAGS_optional_counter_tests) {
        preTestOptionalLbCounters(*lb);
    }
    tester.setBpfProgFd(balancer_prog_fd);
    if(FLAGS_test_from_fixturesm) {
        runTestFromFixtures(*lb, tester, testParam);
        if(FLAGS_install_features_mask > 0 || FLAGS_remove_features_mask > 0) {
            testInstallAndRemoveFeatures(*lb);
            runTestFromFixtures(*lb, tester, testParam);
        } else if(!FLAGS_reloaded_balancer_prog.empty()) {
            auto res = lb->reloadBalancerProg(FLAGS_reloaded_balancer_prog);
            if(!res) {
                LOG(INFO) << "can not reload balancer prog";
                return 1;
            }
            listFeatures(*lb);
            runTestFromFixtures(*lb, tester, testParam);
        }
        return 0;
    }
    prepareLbData(*lb);
    if(!FLAGS_pcap_input.empty()) {
        tester.testPcktsFromPcap();
        return 0;
    } else if(FLAGS_perf_testing) {
        preparePerfTestingLbData(*lb);
        tester.testPerfFromFixture(FLAGS_repeat, FLAGS_position);
    }
    return 0;

    
//------------------------------------2025-2-16-------------------------------

//------------------------------------2025-2-17/9-------------------------------














}
