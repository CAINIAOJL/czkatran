#include "MonitoringServiceCore.h"
#include <fcntl.h>
#include <fmt/core.h>
#include <folly/Utility.h>


namespace czkatran {
namespace monitoring {

using SubscriptionResult = MonitoringServiceCore::SubscriptionResult;

bool MonitoringServiceCore:: initialize(std::shared_ptr<czkatranMonitor> monitor) {
    if(initialized_) {
        return true;
    }
    if(monitor == nullptr) {
        LOG(ERROR) << "NULL monitor !";
        return false;
    }

    monitor_ = monitor;
    //eventIds ------> set<EventId>
    auto eventIds = monitor_->getWriterEnabledEvents();

    //对于每个event，设置writer，pipe模式，回调函数
    for(auto& event : eventIds) {
        int pipefd[2];
        int res = pipe2(pipefd, O_NONBLOCK);
        if(res != 0) {
            LOG(ERROR) << fmt::format("Create pipes failed for event {} error: {}", toString(event), res);
            continue;
        }
        //异步管道读者
        auto reader = folly::AsyncPipeReader::newReader(
            reader_thread_.getEventBase(),
            folly::NetworkSocket::fromFd(pipefd[0])
        );
        //异步管道写者
        auto writer = folly::AsyncPipeWriter::newWriter(
            reader_thread_.getEventBase(),
            folly::NetworkSocket::fromFd(pipefd[1])
        );

        auto cb = std::make_unique<EventPipeCallback>(event);
        cb->enable();
        reader->setReadCB(cb.get());
        readers_.insert({event, std::move(reader)}); //记录
        Events_to_cbs_.insert({event, std::move(cb)});
        /*
        我们希望 monitor 持有指向写入器的弱指针，因为
        我们不知道这个处理程序以及 reader 事件库是否是
        将在 Katran Monitor 之前/之后销毁。如果此处理程序和
        其 Reader 事件库在 Katran 监视器之前被销毁，当
        katran 监视器稍后被销毁，我们不需要这个 AsyncPipeWriter
        要调用其 DTor COZ，它将尝试引用 Reader 事件库
        ，并且会导致 Segfault。
        TODO：弃用 weak_ptr
        */
       //这段话强调了生命周期的重要性，我们要确保监视器对象的生命周期长于事件处理对象，这样才能保证指针不为空，否则会发生段错误。
       std::shared_ptr<folly::AsyncPipeWriter> shared_writer = std::move(writer);
       writers_.insert({event, shared_writer});
       monitor_->setAsyncPipeWriter(event, shared_writer);

       enabled_events_.insert(event);
    }
    initialized_ = true;
    return true;
}

void MonitoringServiceCore:: teardown() {
    if(initialized_) {
        // Events_to_cbs_ =  eventid------------->EventPipeCallcack
        for(auto& eventcb : Events_to_cbs_) {
            eventcb.second->disable();
        }

        if(monitor_) {
            for(auto& eventid : enabled_events_) {
                monitor_->unsetAsyncPipeWriter(eventid);
            }
        }
    }
}

SubscriptionResult MonitoringServiceCore:: acceptSubscription(const EventIds& requested_events) {
    CHECK(initialized_);
    ClientId new_cid;
    EventIds new_subscription_events;

    if(enabled_events_.size() == 0) {
        LOG(ERROR) << "No events enabled";
        return SubscriptionResult(ResponseStatus::NOT_SUPPORTED);
    }
    //没有事件被请求,也是可以的
    if(requested_events.size() == 0) {
        LOG(ERROR) << "No events requested";
        return SubscriptionResult(ResponseStatus::OK);
    }

    {
        //多线程操作，独占作用域
        auto size = subscription_map_.rlock()->size(); //读锁
        if(size >= client_limit) {
            LOG(ERROR) << "Too many clients, failed to accept new sub! ";
            return SubscriptionResult(ResponseStatus::TOOMANY_CLIENTS);
        }
    }
    
    //这个函数用于比较两个容器之间是否有交集，并且将交集插入到另一个新的容器之中，返回一个迭代器
    //比较两者是否有交集，意味着是否允许加入
    std::set_intersection(enabled_events_.begin(), enabled_events_.end(),
                           requested_events.begin(), requested_events.end(),
                           std::inserter(new_subscription_events, new_subscription_events.end()));
    //=0 意味着没有交集
    if(new_subscription_events.size() == 0) {
        LOG(ERROR) << "No events requested are enabled";
        return SubscriptionResult(ResponseStatus::NOT_SUPPORTED);
    }

    {
        //这个变量用于赋值给客户端，并且是线程安全的
        auto new_cid_ptr = curr_id.wlock();//写锁
        new_cid = (*new_cid_ptr)++;//先赋值，再++
    }

    //合法的状态
    return SubscriptionResult(
        ResponseStatus::OK,
        new_cid,
        new_subscription_events,
        //重点，生命周期的问题
        //我们的MonitoringServiceCore对象是继承于SubsrciptionCallback的，可以进行指针转换(向基类方向)，确保了此刻MonitoringServiceCore对象的生命周期长于SubsrciptionCallback
        std::dynamic_pointer_cast<SubsrciptionCallback>(shared_from_this())
    );

}

void MonitoringServiceCore:: onClientCanceled(ClientId cid) {
    cancelSubscription(cid);
}

bool MonitoringServiceCore:: onClientSubscribed(
            ClientId cid,
            std::shared_ptr<ClientSubscriptionIf> sub,
            const EventIds& subscribed_events 
        )
{
    return addSubscription(cid, sub, subscribed_events);
}

ClientSubscriptionMap MonitoringServiceCore:: getSubscriptionMapForEvent(EventId eventid) {
    CHECK(initialized_);
    //ClientSubscriptionMap = clientid --------> ClientSubscriptionIf
    ClientSubscriptionMap sub_map;
    //subscription_map_= clientid --------> ClientSubscriptionIf
    auto submap = subscription_map_.rlock();//读锁
    for(const auto &it : *submap) {
        //Client_to_EventIds_= clientid --------> set<eventid>
        auto clientAndEventIds = Client_to_EventIds_.find(it.first);
        //clientAndEventIds = iterator[clientid --------> set<eventid>]
        if(clientAndEventIds != Client_to_EventIds_.end() && 
            clientAndEventIds->second.find(eventid) != clientAndEventIds->second.end()) {
            //找到了
            sub_map.insert({it.first, it.second});
        }
    }
    return sub_map;
}

bool MonitoringServiceCore:: addSubscription(
            ClientId cid,
            std::shared_ptr<ClientSubscriptionIf> sub,
            const EventIds& subscribed_events
        )
{
    /*
    flowchart TD
    A[开始] --> B{检查是否初始化}
    B -->|未初始化| F[返回错误]
    B -->|已初始化| C[创建回调指针向量]
    C --> D[遍历订阅事件ID]
    D --> E{查找事件回调}
    E -->|未找到| G[记录错误并返回失败]
    E -->|找到| H[添加回调指针到向量]
    H --> I[遍历回调指针向量]
    I --> J[为每个回调添加客户端订阅]
    J --> K[获取订阅映射锁]
    K --> L[插入客户端ID和订阅对象]
    L --> M[记录客户端订阅的事件ID]
    M --> N[返回成功]
    */
    CHECK(initialized_);
    std::vector<EventPipeCallback*> cbs;
    for(const auto& eventid : subscribed_events) {
        //Events_to_cbs_ = eventid ----> EventPipeCallback
        //event_cb = iterator[eventid ----> EventPipeCallback]
        auto event_cb = Events_to_cbs_.find(eventid);
        if(event_cb == Events_to_cbs_.end()) {
            LOG(ERROR) << "Cannot find read callback for event " << eventid;
            return false;
        }
        cbs.push_back(event_cb->second.get());
    }

    for(auto& cb : cbs) {
        cb->addClientSubscription({cid, sub});
    }
    //原子操作
    auto subsmap = subscription_map_.wlock();//写锁
    subsmap->insert({cid, sub});
    Client_to_EventIds_.insert({cid, subscribed_events});

    return true;
}

void MonitoringServiceCore:: cancelSubscription(ClientId cid) {
    CHECK(initialized_);
    //Client_to_EventIds_: clientid ----> set<event>
    auto clientAndevents = Client_to_EventIds_.find(cid);
    //clientAndEvents = iterator[clientid ----> set<event>]
    if(clientAndevents == Client_to_EventIds_.end()) {
        LOG(ERROR) << fmt::format("client {} has no associated events", cid);
        for(auto &eventAndCallback : Events_to_cbs_) {
            //清除关联数据
            //eventAndCallback = iterator[eventid ----> EventPipeCallback]
            eventAndCallback.second->removeClientSubscription(cid);
        }
    } else {
        //clientAndevents != client_to_event_ids_.end()
        //有关联的event映射到事件的回调函数
        for(const auto& eventid : clientAndevents->second) {
            auto eventAndCallback = Events_to_cbs_.find(eventid);
            //eventAndCallback = iterator[eventid ----> EventPipeCallback]
            if(eventAndCallback != Events_to_cbs_.end()) {
                eventAndCallback->second->removeClientSubscription(clientAndevents->first);
            }
        }
    }

    auto subsmap = subscription_map_.wlock();//写锁
    subsmap->erase(cid);
}

}
}