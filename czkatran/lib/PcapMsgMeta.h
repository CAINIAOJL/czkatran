#pragma once

#include "MonitoringStructs.h"
#include "PcapMsg.h"

namespace czkatran {

//这个类是PcapMsg加上extra信息的类
class PcapMsgMeta {
    public:
        PcapMsgMeta() {}
        
        //只允许移动构造，禁止拷贝构造
        PcapMsgMeta(PcapMsg&& msg, uint32_t event);

        PcapMsgMeta(PcapMsgMeta&& other) noexcept;

        PcapMsgMeta(const PcapMsgMeta& other) = delete;    
        
        ~PcapMsgMeta() {}

        PcapMsgMeta& operator=(const PcapMsgMeta& other) = delete;

        PcapMsgMeta& operator=(PcapMsgMeta&& other) noexcept;

        PcapMsg& getPcapMsg();

        bool isControl() {
            return control_;
        }

        void setControl(bool control) {
            control_ = control;
        }

        bool isRestart() {
            return restart_;
        }

        void setRestart(bool restart) {
            restart_ = restart;
        }

        bool isStop() {
            return stop_;
        }

        void setStop(bool stop) {
            stop_ = stop;
        }

        bool isShutdown() {
            return shutdown_;
        }

        void setShutdown(bool shutdown) {
            shutdown_ = shutdown;
        }

        uint32_t getLimit() {
            return packetLimit_;
        }

        void setLimit(uint32_t limit) {
            packetLimit_ = limit;
        }

        monitoring::EventId getEventId();

    private:
        PcapMsg msg_;
        uint32_t event_ {0};
        uint32_t packetLimit_ {0};
        bool restart_ {false};
        bool control_ {false};
        bool stop_ {false};
        bool shutdown_ {false};


};

}