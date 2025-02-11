#include "EventPipeCallback.h"
#include <fmt/core.h>
#include <folly/Utility.h>
#include <stdint.h>
#include "czkatran/lib/PcapStructs.h"

namespace czkatran {
namespace monitoring {


void EventPipeCallback:: readBuffer(std::unique_ptr<folly::IOBuf>&& buf) noexcept {
    VLOG(4) << __func__ << "ready to send data";
    folly::io::Cursor rcursor(buf.get()); //Cursor - Read-only access
    size_t rec_hdr_sz = sizeof(pcaprec_hdr_s); 
    //
    for(; ;) {
        pcaprec_hdr_s rec_hdr;
        Event msg;
        if(rcursor.canAdvance(rec_hdr_sz)) {
            rec_hdr = rcursor.read<pcaprec_hdr_s>(); //先读取数据包头
        } else {
            LOG(INFO) << "can not read pcaprec_hdr_s, giving up";
            break;
        }

        if(rcursor.canAdvance(rec_hdr.incl_len)) { //从数据包头中判断数据包的长度
            //我们调整rcursor的位置到数据包头的位置，读取完整的数据包（包含包头）
            rcursor.retreat(rec_hdr_sz);
            msg.id = event_id_;
            msg.pcksize = rec_hdr.orig_len;
            //读取数据包的全部内容
            msg.data = std::string(reinterpret_cast<const char*>(rcursor.data()), 
                                    rec_hdr_sz + rec_hdr.incl_len); //数据包头+数据
            rcursor.skip(rec_hdr.incl_len + rec_hdr_sz); //跳过一个数据包(包头+数据)
        } else {
            VLOG(2) << fmt::format("can not read a data message, expecting {} bytes, got {}",
                                    rec_hdr.incl_len, rcursor.length());
            rcursor.retreat(rec_hdr_sz); //调整rcursor的位置到数据包头的位置
            break;
        }
        //发送数据
        if(enabled()) {
            auto subsamp = cb_submap_.rlock();//获取读锁
            for (auto& it : *subsamp) {
                VLOG(4) << fmt::format("sedning message {} to client", toString(event_id_));
                it.second->sendEvent(msg);
            }
        }
    }
    //调整buf中data指针的位置为cursor已经处理过的位置
    buf->trimStart(rcursor.getCurrentPosition());
    if(buf->length() != 0) {
        //如果buf中还有剩余数据，递归调用自己处理剩余数据
        readBuffer_.append(std::move(buf)); //将剩余数据添加到readBuffer_中
    }
}

void EventPipeCallback:: addClientSubscription(std::pair<ClientId, std::shared_ptr<ClientSubscriptionIf>>&& new_sub) {
        ClientId cid = new_sub.first;
        VLOG(4) << __func__ << fmt::format("Adding client {}", cid);

        auto cb_submap = cb_submap_.wlock(); //获取写锁
        auto result = cb_submap->insert({cid, std::move(new_sub.second)});
        if(!result.second) {
            LOG(ERROR) << fmt::format("Client {} already subscribed", cid);
        }
}

void EventPipeCallback:: removeClientSubscription(ClientId client_id) {
    VLOG(4) << __func__ << fmt::format("Removing client {}", client_id);

    auto cb_submap = cb_submap_.wlock(); //获取写锁
    auto it = cb_submap->erase(client_id);
    if(it != 1) {
        LOG(ERROR) << fmt::format("Client {} not found in subscription map", client_id);
    }
}






















}
}