#include "PcapMsg.h"

namespace czkatran {


PcapMsg::PcapMsg() {
    pckt_ = nullptr;
}

PcapMsg::PcapMsg(const char* pckt, uint32_t origlen, uint32_t capturedLen)
                : origLen_(origlen), capturedLen_(capturedLen) 
{ 
    if (pckt != nullptr) {
        //从pckt中截取capturedLen个字节
        pckt_ = folly::IOBuf::copyBuffer(pckt, capturedLen);
    }      
    
}

PcapMsg::~PcapMsg() {

}

PcapMsg& PcapMsg::operator=(PcapMsg&& msg) noexcept {
    pckt_ = std::move(msg.pckt_);
    origLen_ = msg.origLen_;
    capturedLen_ = msg.capturedLen_;
    return *this;
}

/*PcapMsg:: PcapMsg(PcapMsg&& msg) noexcept {
    *this = std::move(msg); //可以吗？
}*/

PcapMsg::PcapMsg(PcapMsg&& msg) noexcept
            :pckt_(std::move(msg.pckt_)),
            origLen_(msg.origLen_),
            capturedLen_(msg.capturedLen_)
{

}

}