#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

#include <glog/logging.h>
#include "/home/jianglei/czkatran/czkatran/lib/BpfAdapter.h"
#include "/home/jianglei/czkatran/czkatran/lib/Testing/PacketAttributes.h"
#include "/home/jianglei/czkatran/czkatran/lib/Testing/PcapParser.h"
#include "/home/jianglei/czkatran/czkatran/lib/czkatranLb.h"

namespace czkatran {

//structure with config for run tests from fixtures: fixture(固定的物品，意思是测试数据)
struct TesterConfig {
    
    //存储测试用例的文件路径的向量
    std::vector<PacketAttributes> testData;

    //输出文件的路径
    std::string outputFileName;

    //输出文件的路径
    std::string inputFileName;

    //BPF程序的文件描述符
    int bpfProgFd {-1};

    std::optional<int> singleTestRunPacketNumber_ {std::nullopt};

};

//遇到什么写什么
//内容太多，没必要全写，测试什么些什么

class BpfTester {
    public:
        //constructor
        explicit BpfTester(const TesterConfig& config);

        /**
         * @brief print packets to stdout in base64 format
         */
        void printPktsBase64();

        /**
         * @brief 设置BPF程序的文件描述符
         */
        void setBpfProgFd(const int prog_fd);

        /**
         * @brief 测试从.pcap文件中读取数据包
         */
        void testPcktsFromPcap();

        /**
         * @brief 测试从测试用例中读取数据包
         */
        bool testFromFixture();

        void testPerfFromFixture(uint32_t repeat, const int position);



        /**
         * @brief 将packet以pcap格式写入output文件
         * @param buf 待写入的packet[unique_ptr]（folly::IOBuf）
         */
        void writePcapOutput(std::unique_ptr<folly::IOBuf>&& buf);






        private:
            bool runBpfTesterFromFixture(int prog_fd,
                                         std::unordered_map<int, std::string>& retvalTranslation,
                                         std::vector<void*>ctxs_in,
                                         uint32_t ctx_size = 0);
            
            uint64_t getGloballruRoutedPackets();

            TesterConfig config_; //config for the test
            //PcapParser parser_; //pcap parser 
            BpfAdapter adapter_; //bpf adapter
            czKatranLb* czkatranLb_; //czkatran 
            PcapParser parser_; //pcap parser 

};




}