#pragma once

#include <cstdint>
#include <set>
#include <unordered_map>
#include <memory>
#include <ostream>
#include <string>

namespace czkatran {

namespace monitoring {

constexpr auto KDefaultClientLimit = 10;


enum class EventId : uint8_t {
    TCP_NONSYN_LRUMISS = 0,
    PACKET_TOOBIG = 1,
    QUIC_PACKET_DROP_NO_REAL = 2,
    UNKNOWN = 255,
};

extern std::set<EventId> KAllEventIds;

enum ResponseStatus {
    OK = 0,
    NOT_SUPPORTED = 1,
    TOOMANY_CLIENTS = 2,
    INIERNAL_ERROR = 3,
};

std::string toString(const EventId& EventId); //转化为string

std::ostream& operator<<(std::ostream& os, const EventId& eventId);

struct Event {
    EventId id;
    uint32_t pcksize;
    std::string data;
};

using ClientId = uint32_t;
using EventIds = std::set<EventId>;

//用于存储订阅事件和发布者的帮助程序类
class ClientSubscriptionIf {
    public:
        virtual ~ClientSubscriptionIf() = default;
        
        /**
         * @brief 发送订阅事件
         * @param event 事件
         */
        virtual void sendEvent(const Event& event) = 0;

        virtual void hasEvent(const EventId& eventid) = 0;

        using ClientSubscriptionMap = 
            std::unordered_map<ClientId, std::shared_ptr<ClientSubscriptionIf>>;
};

}
}