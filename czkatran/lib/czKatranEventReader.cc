#include "czKatranEventReader.h"
#include "Balancer_structs.h"

#include <folly/Utility.h>
#include <unistd.h>


namespace czkatran {


void czkatranEventReader::handlePerfBufferEvent(int cpu, 
                                                const char* data, 
                                                size_t size) noexcept
{
    if(size < sizeof(struct event_metadata)) {
        LOG(ERROR) << "Invalid event size: " << size << " less than sizeof(struct event_metadata))";
        return;
    }

    auto mdata = (struct event_metadata*)data;
    PcapMsg pcapmsg (data + sizeof(struct event_metadata), mdata->pkt_len, mdata->data_len);
    PcapMsgMeta pcapmsgmeta (std::move(pcapmsg), mdata->events);
    auto res = queue_->write(std::move(pcapmsgmeta));
    if(!res) {
        LOG(ERROR) << "writer queue is full";
    } else {
        LOG(INFO) << __func__
                  << "write perf event to queue success, queue stats: "
                  << queue_->size()
                  << " / "
                  << queue_->capacity();
    }
}


}