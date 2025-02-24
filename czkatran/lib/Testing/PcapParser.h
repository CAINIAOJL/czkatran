#pragma once

#include <string>
#include <memory>

#include <folly/File.h>
#include <folly/io/IOBuf.h>

//#include "/home/jianglei/czkatran/czkatran/lib/PcapStructs.h"
#include "/home/cainiao/czkatran/czkatran/lib/PcapStructs.h"


namespace czkatran {

//解析Pcap文件的类
class PcapParser {

    public:
        //构造函数
        PcapParser(const std::string& inputFile = "", const std::string& outputFile = "");

        //析构函数
        ~PcapParser();


        /**
         * @brief 一次从pcap文件中读取一个数据包，返回IOBuf类型的独占指针，如果文件中没有数据包，则返回nullptr
         */
        std::unique_ptr<folly::IOBuf> getPacketFromPcap();

        /**
         * @brief 将提供的encodedPckt数据包转化为base64编码，返回IOBuf类型的独占指针，如果数据包格式错误，则返回nullptr
         */
        std::unique_ptr<folly::IOBuf> getPacketFromBase64(const std::string& encodedPckt);

        /**
         * @brief 将提供的IOBuf类型的独占指针数据包转化为base64编码，返回base64编码字符串
         */
        std::string convertPacketToBase64(std::unique_ptr<folly::IOBuf> pckt);

        /**
         * @brief 从Pcap文件中读取数据包，转化为string类型的base64编码，返回base64编码字符串
         */
        std::string getPacketFromPcapBase64();

        /**
         * @brief 读取Pcap文件中的数据包，并写入到输出文件中，返回是否成功  
         * @param packet 要写入的IOBuf类型的独占指针数据包
         * @return 是否成功写入 0 成功，其他失败
         */
        bool writePacket(std::unique_ptr<folly::IOBuf> packet);

    private:

        bool firstRead_ {true};
        bool firstWrite_ {true};


        //输入和输出的Pcap文件路径
        std::string inputFileName_;
        std::string outputFileName_;


        folly::File inputFile_;
        folly::File outputFile_;
        

        uint32_t snaplen_ {0};


};




}
