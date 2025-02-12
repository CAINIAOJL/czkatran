#include "BpfTester.h"


#include <fmt/core.h>
#include <folly/String.h>
#include <folly/io/IOBuf.h>
#include <iostream>



namespace czkatran {

namespace {
    constexpr uint64_t kMaxXdpPktSize = 4096;
    constexpr int KTestRepeatCount = 1;
    std::unordered_map<int, std::string> kXdpCodes {
        {0, "XDP_ABORTED"},
        {1, "XDP_DROP"},
        {2, "XDP_PASS"},
        {3, "XDP_TX"},
    };

    std::unordered_map<int, std::string> kTcCode {
        {-1, "TC_ACT_UNSPEC"},
        {0, "TC_ACT_OK"},
        {1, "TC_ACT_RECLASSIFY"},
        {2, "TC_ACT_SHOT"},
        {3, "TC_ACT_PIPE"},
        {4, "TC_ACT_STOLEN"},
        {5, "TC_ACT_QUEUED"},
        {6, "TC_ACT_REPEAT"},
        {7, "TC_ACT_REDIRECT"},
    };
    constexpr uint32_t kNanosecInSec = 1000000000;
}

BpfTester:: BpfTester(const TesterConfig& config):
    config_(config),
    parser_(config.inputFileName, config.outputFileName),
    adapter_(false) {}
                                                

void BpfTester:: printPktsBase64() {
    if(config_.inputFileName.empty()) {
        LOG(INFO) << "can not print pkts, input file name is empty";
        return;
    }
    std::string pckt;
    while(1) {
        pckt = parser_.getPacketFromPcapBase64();
        if(pckt.empty()) {
            VLOG(2) << "we have read all packets from pcap file";
            break;
        }
        std::cout << pckt << std::endl; //输出base64编码的包
    }
}

void BpfTester:: setBpfProgFd(const int prog_fd) {
    config_.bpfProgFd = prog_fd;
}

void BpfTester:: writePcapOutput(std::unique_ptr<folly::IOBuf>&& buf) {
    if(config_.outputFileName.empty()) {
        VLOG(2) << "output file name is empty, can not write pcap output";
        return;
    }

    auto success = parser_.writePacket(std::move(buf));
    if(!success) {
        LOG(INFO) << "failed to write pcap output"
                  << " to file: " << config_.outputFileName;
    }
}


void BpfTester:: testPcktsFromPcap() {
    if(config_.inputFileName.empty() || config_.bpfProgFd < 0) {
        LOG(INFO) << "can not test packets, "
                  <<"input file name or bpf program fd is empty";
        return;
    }

    uint32_t output_pckt_size {0};
    uint32_t prog_ret_val {0};
    uint64_t pckt_num {1};

    while(true) {
        auto buf = folly::IOBuf::create(kMaxXdpPktSize);
        ///////////////////////////////////////
        auto pckt = parser_.getPacketFromPcap();
        if(pckt == nullptr) {
            VLOG(2) << "we have read all packets from pcap file";
            break;
        }
        ///////////////////////////////////////
        auto res = adapter_.textXdpProg(
            config_.bpfProgFd,
            KTestRepeatCount,
            pckt->writableData(),
            pckt->length(),
            buf->writableData(),
            &output_pckt_size,
            &prog_ret_val);
        if(res < 0) {
            LOG(INFO) << "failed to run bpf test on pckt " << pckt_num;
            ++pckt_num;
            continue;
        }
        if(prog_ret_val > 3) {
            LOG(INFO) << "unsupported return value: " << prog_ret_val;
        } else {
            LOG(INFO) << "xdp run's result from pckt: " << pckt_num
                      << " is " << kXdpCodes[prog_ret_val];
        }
        buf->append(output_pckt_size);
        ///////////////////////////////////////
        writePcapOutput(buf->cloneOne());
        ++pckt_num;
    }
}

bool BpfTester:: testFromFixture() {
    return runBpfTesterFromFixture(config_.bpfProgFd, kXdpCodes, {});
}

bool BpfTester::runBpfTesterFromFixture(int prog_fd,
                                       std::unordered_map<int, std::string>& retvalTranslation,
                                        std::vector<void*>ctxs_in,
                                        uint32_t ctx_size) {
    if(ctxs_in.size() != 0) {
        if(ctx_size == 0) {
            LOG(INFO) << "ctxs_in is not empty buf , ctx_size is 0, can not run bpf test";
            return false;
        }
        if(ctxs_in.size() != config_.testData.size()) {
            LOG(INFO) << "ctxs_in size is not equal to test data size, can not run bpf test";
            return false;
        }
    }

    uint32_t output_pckt_size {0};
    uint32_t prog_ret_val {0};
    uint64_t pckt_num {1};
    std::string ret_val_str;
    std::string test_result;
    uint64_t packetRoutedThroughGloballrubefore {0};
    uint64_t packetRoutedThroughGloballruafter {0};

    bool overallSuccess{true};

    for(int i = 0; i < config_.testData.size(); i++) {
        bool iterationSuccess = true;
        
        if(config_.singleTestRunPacketNumber_ && 
            *config_.singleTestRunPacketNumber_ != (i + 1)) {
                pckt_num++;
                VLOG(2) << "skipping test for packet #" << i;
                continue;
        }
        void* ctx_in = ctxs_in.size() != 0 ? ctxs_in[i] : nullptr;
        auto pckt_buff = folly::IOBuf::create(kMaxXdpPktSize);
        ///////////////////////////////////////////////////
        auto input_pckt = parser_.getPacketFromBase64(config_.testData[i].inputPacket);

        if(config_.testData[i].routeThroughGlobalLru) {
            packetRoutedThroughGloballrubefore = getGloballruRoutedPackets();
        }
        VLOG(2) << "Running test for pckt #" << pckt_num
                << " wtih description: " << config_.testData[i].description;
        LOG(INFO) << "Running test for pckt #" << pckt_num
                  << " wtih description: " << config_.testData[i].description;
        auto res = adapter_.textXdpProg(
            prog_fd,
            KTestRepeatCount,
            input_pckt->writableData(),
            input_pckt->length(),
            pckt_buff->writableData(),
            &output_pckt_size,
            &prog_ret_val,
            nullptr,
            ctx_in,
            ctx_size);
        if(res < 0) {
            LOG(INFO) << "failed to run bpf test on pckt #" << pckt_num
                      << errno << " : " << folly::errnoStr(errno);
            ++pckt_num;
            overallSuccess = false;
            continue;
        }
        if(config_.testData[i].routeThroughGlobalLru) {
            packetRoutedThroughGloballruafter = getGloballruRoutedPackets();
        }
        bool packetRoutedThroughGloballru = ((packetRoutedThroughGloballruafter - packetRoutedThroughGloballrubefore) == 1);

        auto ret_val_iter = retvalTranslation.find(prog_ret_val);
        if(ret_val_iter == retvalTranslation.end()) {
            ret_val_str = "UNKNOWN";
        } else {
            ret_val_str = ret_val_iter->second;
        }

        pckt_buff->append(output_pckt_size);
        writePcapOutput(pckt_buff->cloneOne());

        if(ret_val_str != config_.testData[i].expectedReturnValue) {
            VLOG(2) << "value from test: " << ret_val_str
                    << " expected value: " << config_.testData[i].expectedReturnValue;
            test_result = "\033[31mFailed\033[0m"; //转化为红色
            iterationSuccess = false;
        }

        if(iterationSuccess && config_.testData[i].routeThroughGlobalLru) {
            if(*config_.testData[i].routeThroughGlobalLru && 
               !packetRoutedThroughGloballru) {
                VLOG(2) << "packet should have been routed through global lru, but was not routed";
                test_result = "\033[31mFailed\033[0m"; //转化为红色
                iterationSuccess = false;
            } else if(!*config_.testData[i].routeThroughGlobalLru &&
                      packetRoutedThroughGloballru) {
                    VLOG(2) << "packet should not have been routed through global lru, but was routed";
                    test_result = "\033[31mFailed\033[0m"; //转化为红色
                    iterationSuccess = false;
            }
        }
        if(iterationSuccess) {
            test_result = "\033[32mPassed\033[0m";
            auto output_test_pckt = parser_.convertPacketToBase64(std::move(pckt_buff));
            if(output_test_pckt != config_.testData[i].expectedOutputPacket) {
                VLOG(2) << "output packet not equal to expected output packet"
                        << config_.testData[i].expectedOutputPacket
                        << " vs output_test_pckt: " 
                        << output_test_pckt;
                test_result = "\033[31mFailed\033[0m"; //转化为红色
                iterationSuccess = false;
            } 
        }
        //最终，是否所有测试都成功，取决于iterationSuccess是否为true
        overallSuccess = overallSuccess && iterationSuccess;

        VLOG(2) << "pckt #" << pckt_num;
        LOG(INFO) << fmt::format(
            "Test: {:60} result: {}", config_.testData[i].description, test_result
        );
        pckt_num++;
    }
    return overallSuccess;
}

void BpfTester:: testPerfFromFixture(uint32_t repeat, const int position) {
    int first_index {0}, last_index {0};
    uint32_t duration {0}; //时间间隔
    uint64_t pckt_num {0};
    std::string ret_val_str;
    std::string test_result;
    //2025-1-9-21:50
    if(position < 0 || position >= config_.testData.size()) {
        first_index = 0;
        last_index = config_.testData.size();
    } else {
        first_index = position;
        last_index = first_index + 1;
    }

    for(int i = first_index; i < last_index; i++) {
       auto buf = folly::IOBuf::create(kMaxXdpPktSize);
       auto  input_packet = parser_.getPacketFromBase64(config_.testData[i].inputPacket);
       auto res = adapter_.textXdpProg(
        config_.bpfProgFd,
        repeat,
        input_packet->writableData(),
        input_packet->length(),
        buf->writableBuffer(),
        nullptr,
        nullptr,
        &duration
       );
       if(res < 0) {
        LOG(INFO) << "failed to run bpf test on pckt #" << pckt_num;
        pckt_num++;
        continue;
       }
       VLOG(2) << "pckt # " << pckt_num;
       //调整间隔
       if (duration == 0) {
        duration = 1;
       }
       auto pps = kNanosecInSec / duration;
        LOG(INFO) << fmt::format(
            "Test: {:60} duration: {:10} ns/pckt or {} PPS",
            config_.testData[i].description,
            duration,
            pps
        );
        pckt_num++;
    }
}
                                    
uint64_t BpfTester:: getGloballruRoutedPackets() {
    auto globallru_stats = czkatranLb_->getGlobalLruStats();
    return globallru_stats.v2;
}



}