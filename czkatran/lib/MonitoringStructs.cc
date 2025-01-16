#include "MonitoringStructs.h"

namespace czkatran {

namespace monitoring {


std::set<EventId> KAllEventIds = {
    EventId::TCP_NONSYN_LRUMISS,
    EventId::PACKET_TOOBIG,
    EventId::QUIC_PACKET_DROP_NO_REAL,
};


std::string toString(const EventId& EventId) {
    switch (EventId) {
        case EventId::TCP_NONSYN_LRUMISS:
            return "TCP_NONSYN_LRUMISS";
        case EventId::PACKET_TOOBIG:
            return "PACKET_TOOBIG";
        case EventId::QUIC_PACKET_DROP_NO_REAL:
            return "QUIC_PACKET_DROP_NO_REAL";
        default:
            return "Unknown EventId";
    }
    return "";
}

//重载<<运算符
//std::cout << id << std::endl;
//输出 to_string(id)
std::ostream& operator<<(std::ostream& os, const EventId& eventId) {
    os << toString(eventId);
    return os;
}



}
}