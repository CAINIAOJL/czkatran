#pragma once

#include "DataWriter.h"

#include <folly/MPMCQueue.h> //适合多生产者，多消费者的高性能队列
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "PcapMsgMeta.h"
#include "MonitoringStructs.h"

struct PcapWritesStats {
    uint32_t limit {0};
    uint32_t amount {0};
    uint32_t bufferfull {0};
};


namespace czkatran {

class PcapWriter {

    public:
        /**
         * @brief 构造函数
         * @param datawriter 写入数据的DataWriter
         * @param packetLimit 一次可以写入的最大包数, 0 意味着无上限
         * @param snaplen 最大存储字节数
         */
        explicit PcapWriter(std::shared_ptr<DataWriter> datawriter,
                            uint32_t packetLimit,
                            uint32_t snaplen);
        
        /**
         * @brief 构造函数
         * @param dataWrites 写入数据的DataWriter集合
         * @param packetLimit 一次可以写入的最大包数, 0 意味着无上限
         * @param snaplen 最大存储字节数
         */
        PcapWriter(std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>datawriter,
                    uint32_t packetLimit,
                    uint32_t snaplen);

        /**
         * @brief 启动函数
         * @param queue 一个接受PcapMsg的队列（shared_ptr）
         */
        void run(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue);

        //void runMutil(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue);

        void runMutil(std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue);

        uint32_t packetCaptured() const {
            return packetAmount_;
        }
        
        /**
         * @brief 获取统计信息
         */
        PcapWritesStats getStats();

        std::shared_ptr<DataWriter> getDataWriter(monitoring::EventId eventid) {
            auto it = dataWrites_.find(eventid);
            if(it == dataWrites_.end()) {
                return nullptr;
            }
            return it->second;
        }
        
        /**
         * @brief 重置DataWriter
         */
        void resetWriters(std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>&& newDataWrites);

        //开启事件
        bool enableEvent(monitoring::EventId eventid) {
            return enablesEvents_.insert(eventid).second;
        }

        //关闭事件
        void disableEvent(monitoring::EventId eventid) {
            enablesEvents_.erase(eventid);
        }   

        //重新设置包数限制
        void overridePacketLimit(bool value) {
            packetLimitOverride_ = value;
        }

    private:
        /**
         * @brief 写pcap包
         * @param msg 待写入的包
         * @param writeId 事件id
         */
        void writePacket(const PcapMsg& msg, monitoring::EventId writeId);

        /**
         * @brief 写pcap头
         * @param writeId 事件id
         */
        bool writePcapHeader(monitoring::EventId writeId);

        /**
         * @brief 重启DataWriter
         */
        void restartWriters(uint32_t packetLimit);

        /**
         * @brief 停止DataWriter
         */
        void stopWriters();

        std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>
                dataWrites_; // 存储不同事件的DataWriter

        std::set<monitoring::EventId> enablesEvents_; // 开启的事件

        std::set<monitoring::EventId> headerExists_; // 已经写入pcap头的事件

        //可以写入的最大包数
        uint32_t packetLimit_ {0};

        //已经写入的包数
        uint32_t packetAmount_ {0};

        //是否写满了
        uint32_t bufferFull_ {0};

        //最大存储字节数
        const uint32_t snaplen_ {0};
        
        //锁
        std::mutex cntrLock_;

        bool packetLimitOverride_ {false};

};


}





