#include <iostream>
#include <string>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "/home/jianglei/czkatran/czkatran/decap/XdpDecap.h"
#include "/home/jianglei/czkatran/czkatran/decap/testing/XdpDecapTestFixtures.h"
#include "XdpDecapGueTestFixtures.h"
#include "XdpDecapTestFixtures.h"
#include "/home/jianglei/czkatran/czkatran/lib/Testing/BpfTester.h"

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(decap_prog, "./decap_kern.o", "path to balancer bpf prog");
DEFINE_bool(print_base64, false, "print packet in base64 from pcap file");
DEFINE_bool(test_from_fixtures, false, "run tests on predefined dataset");
DEFINE_bool(gue, false, "run GUE tests instead of IPIP ones");
DEFINE_bool(perf_testing, false, "run perf tests on predefined dataset");
DEFINE_int32(repeat, 100000, "perf test runs for single packet");
DEFINE_int32(postion, -1, "perf test runs for single packet");


void testxdpDecapCounters(czkatran::XdpDecap& decap) {
    LOG(INFO) << "Testing counter's sanity"; //测试计数器的健全性
    auto stats = decap.getXdpDecapStats();

    //预测顺利的数据，我们先写，边写边分析
    int expectedV4DecapPkts = 1;  //?
    int expectedV6DecapPkts = FLAGS_gue? 9 : 2; //?
    int expectedTotalDecapPkts = FLAGS_gue ? 10 : 7; //?
    int expectedTotalTPRPkts = 4;  //?
    int expectedMisroutedTPRPkts = 3;  //?

    if(stats.decap_v4 != expectedV4DecapPkts || 
       stats.decap_v6 != expectedV6DecapPkts ||
       stats.total != expectedTotalDecapPkts ||
       stats.tpr_misrouted != expectedMisroutedTPRPkts ||
       stats.tpr_total != expectedTotalTPRPkts) {
        LOG(ERROR) << "decap_v4 pkts:" << stats.decap_v4
                   << " expected:" << expectedV4DecapPkts
                   << " decap_v6 pkts:" << stats.decap_v6
                   << " expected:" << expectedV6DecapPkts
                   << " total pkts:" << stats.total
                   << " expected:" << expectedTotalDecapPkts
                   << " tpr_misrouted pkts:" << stats.tpr_misrouted
                   << " expected:" << expectedMisroutedTPRPkts
                   << " tpr_total pkts:" << stats.tpr_total
                   << " expected:" << expectedTotalTPRPkts;
        return;
    }   

    LOG(INFO) << "Counter's sanity test passed"; //计数器的健全性测试通过
}

int main(int argc, char* argv[]) {
    //初始化相关组件
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    //初始化测试器
    czkatran::TesterConfig config;
    config.inputFileName = FLAGS_pcap_input;
    config.outputFileName = FLAGS_pcap_output;
    config.testData = FLAGS_gue ? czkatran::testing::gueTestFixtures : czkatran::testing::testFixtures;

    czkatran::BpfTester tester(config);
    if(FLAGS_print_base64) {
        if(FLAGS_pcap_input.empty()) {
            std::cout << "Please provide input pcap file path" << std::endl;
            std::cout << "the pcap_input is not specified exiting" << std::endl;
            return 1;
        }
        tester.printPktsBase64();
        return 0;
    }

    czkatran::XdpDecap decap(czkatran::XdpDecapConfig{FLAGS_decap_prog});
    decap.loadXdpDecap();
    auto decap_prog_fd = decap.getXdpDecapFd();
    tester.setBpfProgFd(decap_prog_fd);
    decap.setServerId(100);

    if(!FLAGS_pcap_input.empty()) {
        tester.testPcktsFromPcap();
        return 0;
    } else if (FLAGS_test_from_fixtures) {
        tester.testFromFixture();
        testxdpDecapCounters(decap);
        return 0;
    } else if (FLAGS_perf_testing) {
        tester.testPerfFromFixture(FLAGS_repeat, FLAGS_postion);
    }
    return 0;
}