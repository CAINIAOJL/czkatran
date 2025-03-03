#include <iostream>
#include <string>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <xdp/libxdp.h>
#include "/home/cainiao/czkatran/czkatran/decap/XdpDecap.h"
#include "XdpDecapGueTestFixtures.h"
#include "XdpDecapTestFixtures.h"
#include "/home/cainiao/czkatran/czkatran/lib/Testing/BpfTester.h"

DEFINE_string(pcap_input, "", "path to input pcap file");
DEFINE_string(pcap_output, "", "path to output pcap file");
DEFINE_string(decap_prog, "decap_kern.o", "path to balancer bpf prog");
DEFINE_bool(print_base64, false, "print packet in base64 from pcap file");
DEFINE_bool(test_from_fixtures, true, "run tests on predefined dataset");
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
        LOG(ERROR) << "\n"
                   << "decap_v4 pkts:" << stats.decap_v4
                   << "\n"
                   << " expected:" << expectedV4DecapPkts
                   << "\n"
                   << " decap_v6 pkts:" << stats.decap_v6
                   << "\n"                   
                   << " expected:" << expectedV6DecapPkts
                   << "\n"                   
                   << " total pkts:" << stats.total
                   << "\n"                   
                   << " expected:" << expectedTotalDecapPkts
                   << "\n"                   
                   << " tpr_misrouted pkts:" << stats.tpr_misrouted
                   << "\n"                   
                   << " expected:" << expectedMisroutedTPRPkts
                   << "\n"                   
                   << " tpr_total pkts:" << stats.tpr_total
                   << "\n"                   
                   << " expected:" << expectedTotalTPRPkts;
        LOG(ERROR) << "[FATL] Incorrect decap counters";
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

    czkatran::XdpDecap decap(czkatran::XdpDecapConfig{.progPath = FLAGS_decap_prog});
    std::cout << "begin loadXdpDecap!" <<std::endl;
    decap.loadXdpDecap();
    std::cout << "loadXdpDecap" <<std::endl;
    auto decap_prog_fd = decap.getXdpDecapFd();
    std::cout << "decap_prog_fd:" << decap_prog_fd << std::endl;
    tester.setBpfProgFd(decap_prog_fd);
    decap.setServerId(100);

    if(!FLAGS_pcap_input.empty()) {
        tester.testPcktsFromPcap();
        return 0;
    } else if (FLAGS_test_from_fixtures) {
        std::cout << "in FLAGS_test_from_fixtures" << std::endl;
        tester.testFromFixture();
        testxdpDecapCounters(decap);
        return 0;
    } else if (FLAGS_perf_testing) {
        tester.testPerfFromFixture(FLAGS_repeat, FLAGS_postion);
    }
    return 0;
}