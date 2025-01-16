#include "PcapMsgMeta.h"

#include <fmt/format.h>
#include <folly/Utility.h>
#include <glog/logging.h>
namespace czkatran {

using EventId = monitoring::EventId;

PcapMsgMeta::PcapMsgMeta(PcapMsg&& msg, uint32_t event)
                    : msg_(std::move(msg)),
                      event_(event)
{

}

PcapMsgMeta:: PcapMsgMeta(PcapMsgMeta&& other) noexcept 
                    : msg_(std::move(other.msg_)),
                      event_(other.event_),
                      packetLimit_(other.packetLimit_),
                      restart_(other.restart_),
                      control_(other.control_),
                      stop_(other.stop_),
                      shutdown_(other.shutdown_)
{

}

PcapMsgMeta& PcapMsgMeta:: operator=(PcapMsgMeta&& other) noexcept {
    msg_ = std::move(other.msg_);
    event_ = other.event_;
    packetLimit_ = other.packetLimit_;
    restart_ = other.restart_;
    control_ = other.control_;
    stop_ = other.stop_;
    shutdown_ = other.shutdown_;
    return *this;
}

PcapMsg& PcapMsgMeta:: getPcapMsg() {
    return msg_;
}

EventId PcapMsgMeta:: getEventId() {
    try {
        return static_cast<EventId>(event_);
    } catch (const std::exception& e) {
        LOG(ERROR) << fmt::format("invalid event id: {}: {}", event_, e.what());
        return EventId::UNKNOWN;
    }
    return EventId::UNKNOWN;
}

}