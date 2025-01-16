#include "PcapWriter.h"

#include <chrono>
#include "PcapStructs.h"

using Guard = std::lock_guard<std::mutex>;

namespace czkatran {
namespace {
constexpr uint32_t kPcapWriterMagic = 0xa1b2c3d4;
constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4;
constexpr int32_t kGmt = 0;
constexpr uint32_t kAccuracy = 0;
constexpr uint32_t kMaxSnapLen = 0xFFFF; // 65535
constexpr uint32_t kEthernet = 1; // lo 

using EventId = monitoring::EventId;
constexpr EventId kDefaultWriter = EventId::TCP_NONSYN_LRUMISS;
}

PcapWriter:: PcapWriter(std::shared_ptr<DataWriter> datawriter,
                            uint32_t packetLimit,
                            uint32_t snaplen) 
                : packetLimit_(packetLimit),
                  snaplen_(snaplen)
{
    dataWrites_.insert({kDefaultWriter, datawriter});    
}

PcapWriter:: PcapWriter(std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>datawriter,
                    uint32_t packetLimit,
                    uint32_t snaplen):
            dataWrites_(datawriter),
            packetLimit_(packetLimit),
            snaplen_(snaplen)     
{
}

void PcapWriter:: writePacket(const PcapMsg& msg, monitoring::EventId writeId) {
    //微妙
    auto unix_usec = 
            std::chrono::duration_cast<std::chrono::microseconds>
            (std::chrono::high_resolution_clock::now().time_since_epoch()).count();

    const uint32_t now_sec = unix_usec / 1000000;
    const uint32_t now_usec = unix_usec - now_sec * 1000000;

    pcaprec_hdr_s rec_hdr = {
        .ts_sec = now_sec,
        .ts_usec = now_usec
    };
    
    rec_hdr.incl_len = msg.getCaptruedLen();
    rec_hdr.orig_len = msg.getOrigLen();
    auto writerit = dataWrites_.find(writeId);
    if(writerit == dataWrites_.end()) {
        LOG(ERROR) << "No writer found for event " << writeId;
        return;
    }
    writerit->second->writeData(&rec_hdr, sizeof(rec_hdr));
    writerit->second->writeData(msg.getRawData(), msg.getCaptruedLen());
}

bool PcapWriter:: writePcapHeader(monitoring::EventId writeId) {
    if (headerExists_.find(writeId) != headerExists_.end()) {
        VLOG(4) << "header already exists for event ";
        return true;
    }
    auto writerit = dataWrites_.find(writeId);
    if(writerit == dataWrites_.end()) {
        LOG(ERROR) << "No writer found for event " << writeId;
        return false;
    }
    //验证空间是否能容下pcap头
    if(!writerit->second->available(sizeof(struct pcap_hdr_s))) {
        LOG(ERROR) << "No space for pcap header";
        return false;
    }
    struct pcap_hdr_s hdr {
        .magic_number = kPcapWriterMagic, .version_major = kVersionMajor,
        .version_minor = kVersionMinor, .thiszone = kGmt, .sigfigs = kAccuracy,
        .snaplen = snaplen_ ?: kMaxSnapLen, .network = kEthernet
    };
    //原本是writerit->second->writedata(&hdr, sizeof(hdr));
    //却导致数据输入错误，原因未知，改为写入头部
    writerit->second->writeHeader(&hdr, sizeof(hdr));
    headerExists_.insert(writeId);
    return true;
}

void PcapWriter:: run(std::shared_ptr<folly::MPMCQueue<PcapMsg>> queue) {
    auto snaplen = snaplen_ ? : kMaxSnapLen;
    if(!writePcapHeader(kDefaultWriter)) {
        LOG(ERROR) << "Failed to write pcap header";
        return;
    }

    PcapMsg msg(nullptr, 0, 0);
    while(packetLimit_ == 0 || packetAmount_ < packetLimit_) {
        queue->blockingRead(msg);
        Guard lock(cntrLock_);
        msg.trim(snaplen);
        if(msg.empty()) {
            LOG(INFO) << "Empty message was received. Writer thread is stopping.";
            break;
        }   
        auto writeIt = dataWrites_.find(kDefaultWriter);
        if(writeIt == dataWrites_.end()) {
            LOG(ERROR) << "No writer found for event " << kDefaultWriter;
        }
        if(!writeIt->second->available(msg.getCaptruedLen() + sizeof(pcaprec_hdr_s))) {
            bufferFull_++;
            break;
        }
        writePacket(msg, kDefaultWriter);
        ++packetAmount_;
    }
}

PcapWritesStats PcapWriter:: getStats() {
    PcapWritesStats stats;
    Guard lock(cntrLock_);
    stats.amount = packetAmount_;
    stats.bufferfull = bufferFull_;
    stats.limit = packetLimit_;
    return stats;
}

void PcapWriter:: restartWriters(uint32_t packetLimit) {
    //Guard lock(cntrLock_);
    headerExists_.clear();

    for(auto & eventWriter : dataWrites_) {
        eventWriter.second->restart();
    }

    packetLimit_ = packetLimit;
    packetAmount_ = 0;
}


void PcapWriter:: stopWriters() {
    for(auto & eventWriter : dataWrites_) {
        eventWriter.second->stop();
    }
    //相关参数归零
    packetLimit_ = 0;
    packetAmount_ = packetLimit_;
}

void PcapWriter:: resetWriters(std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>>&& newDataWrites) {
    Guard lock(cntrLock_);
    for(auto& eventWriter : dataWrites_) {
        eventWriter.second->stop();
    }
    dataWrites_.clear();
    dataWrites_ = std::move(newDataWrites);
}

void PcapWriter:: runMutil(std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue) {
    auto snaplen = snaplen_ ? : kMaxSnapLen;
    PcapMsgMeta msg;
    for(; ; ) {
        VLOG(4) << __func__ << " blocking read PcapMsgMeta";
        queue->blockingRead(msg);
        Guard lock(cntrLock_);
        if(msg.isControl()) {
            if(msg.isShutdown()) {
                VLOG(4) << "shutdown signal received, stopping writer thread";
                break;
            } else if (msg.isRestart()) {
                VLOG(4) << "restart signal received, resetting packet counter";\
                restartWriters(msg.getLimit());
            } else if (msg.isStop()) {
                VLOG(4) << "stop signal received, stopping writer thread";
                stopWriters();
            }
            continue;
        }
        if(!packetLimitOverride_ && packetAmount_ >= packetLimit_) {
            VLOG(4) << "packet limit reached, stopping writer thread";
            continue;
        }
        auto eventId = msg.getEventId();
        if(enablesEvents_.find(eventId) == enablesEvents_.end()) {
            LOG(INFO) << "event " << eventId << " is not enabled, skipping";
            continue;
        }
        if(!writePcapHeader(eventId)) {
            LOG(ERROR) << "DataWriter failed to write a header";
            continue;
        }
        msg.getPcapMsg().trim(snaplen);
        auto writerIt = dataWrites_.find(eventId);
        if(writerIt == dataWrites_.end()) {
            LOG(ERROR) << "No writer found for event " << eventId;
            continue;
        }
        if(!writerIt->second->available(msg.getPcapMsg().getCaptruedLen() + sizeof(pcaprec_hdr_s))) {
            VLOG(4) << "Writer buffer is full. Skipping";
            ++bufferFull_;
            continue;
        }
        VLOG(4) << __func__ << " writing packet for event " << eventId;
        writePacket(msg.getPcapMsg(), eventId);
        ++packetAmount_;
    }
}

}