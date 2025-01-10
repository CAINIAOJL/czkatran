#include "czkatran/lib/Testing/PcapParser.h"
#include "czkatran/lib/Testing/Base64Helpers.h"


#include <glog/logging.h>
#include <folly/FileUtil.h>

namespace czkatran {

namespace {

constexpr uint32_t KPcapWriterMagicNumber = 0xa1b2c3d4; //magic_number
constexpr uint16_t kVersionMajor = 2; //version_major
constexpr uint16_t kVersionMinor = 4; //version_minor
constexpr int32_t kGmt = 0; //thiszone
constexpr uint32_t kAccuracy = 0; //sigfigs
constexpr uint32_t Ksnaplen = 65535; //snaplen
constexpr uint32_t kEthernet = 1; //1 表示以太网 network

PcapParser:: PcapParser(const std::string& inputFile, const std::string& outputFile): inputFileName_(inputFile), outputFileName_(outputFile) 
{
    if(!inputFile.empty()) {
        try
        {
            inputFile_ = folly::File(inputFile);
        }
        catch(const std::exception& e)
        {
            LOG(ERROR) << "expection while opening file (intputfile-Pcap): "
                       << inputFile
                       << " exception: " 
                       << e.what();
            throw;
        }
    }

    if(!outputFile.empty()) {
        try {
            outputFile_ = folly::File(outputFile, O_RDONLY | O_CREAT | O_TRUNC);
        }
        catch(const std::exception& e) {
            LOG(ERROR) << "expection while opening file (outputfile-Pcap): "
                       << outputFile
                       << " exception: " 
                       << e.what();
            throw;
        }
    }
}


PcapParser:: ~PcapParser() {
    //关闭相关文件
    if(!inputFileName_.empty()) {
        auto ret = inputFile_.closeNoThrow();
        if(ret != 0) {
            LOG(INFO) << "close input file failed"
                      << " inputfile: "
                      << inputFileName_;
        }
    }
    if(!outputFileName_.empty()) {
        auto ret = outputFile_.closeNoThrow();
        if(ret != 0) {
            LOG(INFO) << "close output file failed"
                      << " outputfile: "
                      << outputFileName_;
        }
    }
}

std::unique_ptr<folly::IOBuf> PcapParser:: getPacketFromPcap() {
    const struct pcaprec_hdr_s* pcaperc_hdr;
    bool res;
    std::string tempbuff;
    uint32_t pkt_len;
    if(inputFileName_.empty()) {
        LOG(INFO) << "input file is empty";
        return nullptr;
    }

    auto fd = inputFile_.fd(); //获取文件描述符
    //是否是第一次读
    if(firstRead_) {
        //是的话，我们要多读一此整个文件的头部信息---pcap_hdr_s
        firstRead_ = false;
        const struct pcap_hdr_s* pcap_hdr;
        res = folly::readFile(fd, tempbuff, sizeof(struct pcap_hdr_s));
        if(!res) {
            LOG(ERROR) << "read pcap header failed! ";
            return nullptr;
        }
        pcap_hdr = reinterpret_cast<const struct pcap_hdr_s*>(tempbuff.c_str());
        VLOG(2) << "pcap_hdr:\n" << "version_major: " << pcap_hdr->version_major
                << " version_minor: " << pcap_hdr->version_minor
                << " magic_number: " << pcap_hdr->magic_number
                //<< " thiszone: " << pcap_hdr->thiszone //默认为0
                //<< " sigfigs: " << pcap_hdr->sigfigs //默认为0
                << " snaplen: " << pcap_hdr->snaplen
                << " network: " << pcap_hdr->network;
        snaplen_ = pcap_hdr->snaplen;
    }

    res = folly::readFile(fd, tempbuff, sizeof(struct pcaprec_hdr_s));
    if(!res || tempbuff.size() != sizeof(struct pcaprec_hdr_s)) {
        LOG(ERROR) << "read pcaprec header failed! ";
        return nullptr;
    }
    pcaperc_hdr = reinterpret_cast<const struct pcaprec_hdr_s*>(tempbuff.c_str());
    pkt_len = pcaperc_hdr->incl_len; //数据包的长度
    VLOG(2) << "pckt len: " << pcaperc_hdr->incl_len;
    if(pkt_len > snaplen_) {
        LOG(INFO) << "error in pcap file, incl_len > snaplen! ";
        return nullptr;
    }

    res = folly::readFile(fd, tempbuff, pkt_len); //读取真正的数据
    if(!res || tempbuff.size() != pkt_len) {
        LOG(ERROR) << "read pcap data failed! ";
        return nullptr;
    }
    auto iobuf = folly::IOBuf::copyBuffer(tempbuff.c_str(), pkt_len);
    return iobuf;
}

std::unique_ptr<folly::IOBuf>PcapParser:: getPacketFromBase64(const std::string& encodedPckt) {
    auto pckt = Base64Helpers::base64Decode(encodedPckt);
    return folly::IOBuf::copyBuffer(pckt);
}

std::string PcapParser:: convertPacketToBase64(std::unique_ptr<folly::IOBuf> pckt) {
    return Base64Helpers::base64Encode(pckt.get());
}

std::string PcapParser:: getPacketFromPcapBase64() {
    auto buf = getPacketFromPcap();
    if(buf != nullptr) {
        return Base64Helpers::base64Encode(buf.get());
    } else {
        return "";
    }
}

// 2025-1-5-22.55
bool PcapParser:: writePacket(std::unique_ptr<folly::IOBuf> packet) {
    uint32_t pkt_len = packet->length();
    auto fd = outputFile_.fd();

    if(firstWrite_) {
        firstWrite_ = false;
        struct pcap_hdr_s hdr {
            .magic_number = KPcapWriterMagicNumber,
            .version_major = kVersionMajor,
            .version_minor = kVersionMajor,
            .thiszone = kGmt,
            .sigfigs = kAccuracy,
            .snaplen = Ksnaplen,
            .network = kEthernet
        };
        //向output pcap文件写入pcap_hdr_s头部信息
        auto ret = folly::writeFull(fd, &hdr, sizeof(hdr));
        if(!ret) {
            LOG(INFO) << "can not write generic pcap header to output file";
            return false;
        }
    }

    /*
    ts_sec：捕获此数据包的日期和时间。此值以秒为单位，自 1970 年 1 月 1 日 00：00：00 GMT 以来;
        这也称为 UN*X time_t。
        您可以使用 time.h 中的 ANSI C time（） 函数来获取此值，但您可以使用更优化的方式来获取此时间戳值。
        如果此时间戳不是基于 GMT （UTC），请使用全局标头中的 thiszone 进行调整。

    ts_usec：在常规 pcap 文件中，为捕获此数据包时的微秒数，作为 ts_sec 的偏移量。
        在纳秒级文件中，这是捕获数据包时的纳秒级，作为ts_sec ⚠️的偏移量请注意：
        此值不应达到 1 秒（在常规 pcap 文件中为 1 000 000;在纳秒级文件中为 1 000 000 000）;
        在这种情况下，必须增加 ts_sec！
    */
    auto unix_usec =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now().time_since_epoch())
          .count();

    const uint32_t now_sec = unix_usec / 1000000;
    //pcap format ts_usec is a offset in msec after ts_sec
    const uint32_t now_usec = unix_usec - now_sec * 1000000;
    
    pcaprec_hdr_s rec_hdr {
        .ts_sec = now_sec,
        .ts_usec = now_usec,
        .incl_len = pkt_len,
        .orig_len = pkt_len
    };
    //向output pcap文件写入pcaprec_hdr_s头部信息
    auto ret = folly::writeFull(fd, &rec_hdr, sizeof(rec_hdr));
    
    if(!ret) {
        LOG(INFO) << "can not write pcaprec header to output file";
        return false;
    }

    auto ret = folly::writeFull(fd, packet->data(), pkt_len);

    if(!ret) {
        LOG(INFO) << "can not write pcap data to output file";
    }
    return true;
}

}






}