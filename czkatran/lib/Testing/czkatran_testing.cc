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

czkatranTestParam getTestParam() {
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
    auto balancer_prog_fd = lb->getczKatranProgFd();
    if(FLAGS_optional_counter_tests) {

    }

//------------------------------------2025-2-16-------------------------------
















}
