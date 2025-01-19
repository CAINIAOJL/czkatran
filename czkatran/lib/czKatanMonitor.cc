#include "czKatanMonitor.h"

#include <folly/Conv.h>
#include <folly/Utility.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include "FileWriter.h"
#include "IOBuffWriter.h"
#include "PipeWriter.h"
#include "czKatranEventReader.h"
#include "PcapWriter.h"

namespace czkatran {
using monitoring::EventId;

czkatranMonitor:: czkatranMonitor(const struct czKatranMonitorConfig& config):
                                config_(config)
{
    scopedEvb_ = std::make_unique<folly::ScopedEventBaseThread>("czkatran_monitor");
    queue_ = std::make_shared<folly::MPMCQueue<PcapMsgMeta>>(config_.queueSize);
    auto evb = scopedEvb_->getEventBase(); //生命周期与ScopedEventBaseThread一致

    reader_ = std::make_unique<czkatranEventReader>(queue_);
    if(!reader_->open(config_.mapFd, evb, config_.pages)) {
        LOG(ERROR) << "Perf event reader open failed !";
    }

    auto data_writer = createWriters();

    writer_ = std::make_shared<PcapWriter>(data_writer, config.pcktLimit, config.snapLen);

    writer_->overridePacketLimit(config_.storage == PcapStorageFormat::PIPE);
    
    //初始化所有event
    for(auto event : config_.events) {
        enableWriterEvent(event);
    }
    writerThread_ = std::thread([this]() {
        writer_->runMutil(queue_); //线程启动
    });
}

czkatranMonitor:: ~czkatranMonitor() {
    PcapMsgMeta msg;
    msg.setControl(true);
    msg.setShutdown(true);  //设置关闭标志
    queue_->write(std::move(msg));
    writerThread_.join(); //等待线程退出
}

void czkatranMonitor:: stopMonitor() {
    PcapMsgMeta msg;
    msg.setControl(true);
    msg.setStop(true); //设置停止标志
    queue_->write(std::move(msg));
}

void czkatranMonitor:: restartMonitor(uint32_t limit, 
                                     std::optional<PcapStorageFormat> storage) {
    if(storage.has_value() && config_.storage != *storage) {
        stopMonitor(); //zcatran不支持切换存储格式，先停止监控
        config_.storage = *storage;
        writer_->resetWriters(createWriters());
        writer_->overridePacketLimit(config_.storage == PcapStorageFormat::PIPE);
    }
    PcapMsgMeta msg;
    msg.setControl(true);
    msg.setRestart(true);
    msg.setLimit(limit);
    queue_->blockingWrite(std::move(msg));
    VLOG(4) << __func__ << "successfully restart monitor";
}

bool czkatranMonitor:: enableWriterEvent(monitoring::EventId event) {
    if(!writer_) {
        return false;
    }

    return writer_->enableEvent(event);
}

bool czkatranMonitor:: disabledWriterEvent(monitoring::EventId event) {
    if(!writer_) {
        return false;
    }
    writer_->disableEvent(event);
    return true;
}

std::set<monitoring::EventId> czkatranMonitor:: getEnabledEvents() {
    if(!writer_) {
        return {};
    }
    return writer_->getEnableEvents();
}

PcapWritesStats czkatranMonitor:: getPcapWriterStats() {
    return writer_->getStats();
}

std::unique_ptr<folly::IOBuf> czkatranMonitor:: getEventBuffer(monitoring::EventId event) {
    if(buffers_.size() == 0) {
        LOG(ERROR) << "PcapStorageFormat is not set to IOBuf";
        return nullptr;
    }

    auto buffer = buffers_.find(event);
    if(buffer == buffers_.end()) {
        LOG(ERROR) << "Event " << event << " not found in buffer";
        return nullptr;
    }
    return buffer->second->cloneOne();
}

void czkatranMonitor:: setAsyncPipeWriter(monitoring::EventId event, 
                                         std::shared_ptr<folly::AsyncPipeWriter> writer) {
    auto it = pipeWriters_.find(event);
    if(it == pipeWriters_.end()) {
        //emplace返回pair<iterator, bool>，bool为true表示插入成功，false表示已存在
        auto pipeWriter = pipeWriters_.emplace(event, writer);
        CHECK(pipeWriter.second) << "Failed to add pipe writer for event ";
        it = pipeWriter.first;
    } else {
        VLOG(4) << "Event " << event << " already has a pipe writer";
        it->second = writer;
    }

    auto pipewriter = 
        std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
    if(!pipewriter) {
        LOG(INFO) << "no pipe writer for event " << event;
        return;
    }

    pipewriter->setWriterDestination(writer);
    writer_->enableEvent(event);
    VLOG(4) << __func__ << "successfully set async pipe writer";
}

void czkatranMonitor:: unsetAsyncPipeWriter(monitoring::EventId event) {
    auto pipewriter = 
        std::dynamic_pointer_cast<PipeWriter>(writer_->getDataWriter(event));
    if(!pipewriter) {
        LOG(ERROR) << "no pipe writer for event " << event;
        return;
    }
    writer_->disableEvent(event);
    pipewriter->unsetWriterDestination();
    pipeWriters_.erase(event);

    VLOG(4) << __func__ << "successfully unset async pipe writer";
}

std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>> 
czkatranMonitor:: createWriters() {
    std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>> ans;
    for(auto event : config_.events) {
        if(config_.storage == PcapStorageFormat::FILE) {
            std::string fname;
            //fname = config_.path + "_" + event;
            folly::toAppend(config_.path, "_", event, &fname);
            ans.insert(std::make_pair(event, std::make_shared<FileWriter>(fname)));
        } else if (config_.storage == PcapStorageFormat::IOBUF) {
            auto res = buffers_.insert({event, folly::IOBuf::create(config_.bufferSize)});
            ans.insert({event, std::make_shared<IOBuffWriter>(res.first->second.get())});
        } else if (config_.storage == PcapStorageFormat::PIPE) {
            auto it = pipeWriters_.find(event);
            auto pipewriter = std::make_shared<PipeWriter>();
            if(it != pipeWriters_.end()) {
                pipewriter->setWriterDestination(it->second);
            }
            ans.insert({event, std::move(pipewriter)});
        } else {
            LOG(ERROR) << "Unsupported storage format " << static_cast<int>(config_.storage);
        }
    }

    VLOG(4) << __func__ << "successfully create data writers";
    return ans;
}

}