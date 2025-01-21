#pragma once

#include <folly/io/async/AsyncPipe.h>
#include <folly/io/async/DelayedDestruction.h> //延迟销毁
#include <folly/io/async/ScopedEventBaseThread.h>
#include <optional>
#include "czkatranLb.h"
#include "EventPipeCallback.h"
#include "MonitoringStructs.h"
#include "czKatanMonitor.h"

namespace czkatran {
namespace monitoring {

//客户端回调函数
class SubsrciptionCallback {
    public:
        virtual ~SubsrciptionCallback() = default;
        
        //当客户端取消订阅时调用
        virtual void onClientCanceled(ClientId cid) = 0;

        virtual bool onClientSubscribed(
            ClientId cid,
            std::shared_ptr<ClientSubscriptionIf> sub,
            const EventIds& subscribed_events 
        ) = 0;
};

/*
 * 这是监控服务的核心，其中所有订阅逻辑存在。
 * 要使用它，请同时实现 ErrorResultSetterIf 和 OkResultSetterIf。一个 rpc
 * service 不应继承此类，而应将其用于组合。
 */
//第二次遇见std::enable_shared_from_this
//事件发布-订阅模式：对象发布事件，订阅者可能异步处理，发布者需要确保在所有订阅者处理完之前不被销毁。
//示例代码：发布者与订阅者的例子：
/*
class Observer {
public:
    virtual void onNotify() = 0;
};

class Subject : public std::enable_shared_from_this<Subject> {
public:
    void addObserver(std::weak_ptr<Observer> observer) {
        observers.push_back(observer);
    }

    void notifyObservers() {
        for (auto it = observers.begin(); it != observers.end(); ) {
            if (auto obs = it->lock()) {
                obs->onNotify();
                ++it;
            } else {
                // 移除已销毁的观察者
                it = observers.erase(it);
            }
        }
    }

private:
    std::vector<std::weak_ptr<Observer>> observers;
};
*/

class MonitoringServiceCore : public SubsrciptionCallback,
                              public std::enable_shared_from_this<MonitoringServiceCore>
{
    public:
        MonitoringServiceCore() {}

        ~MonitoringServiceCore() override {

        }

        // 创建并返回一个MonitoringServiceCore对象的智能指针
        static std::shared_ptr<MonitoringServiceCore> make() {
            // 使用std::make_shared在共享指针中分配并构造一个MonitoringServiceCore对象
            // 这种方式比直接使用new操作符更高效且更安全，能避免内存泄漏
            return std::make_shared<MonitoringServiceCore>();
        }
        /*
        为了测试功能
        */
        //初始化函数，虚函数
        virtual bool initialize(std::shared_ptr<czkatranMonitor> monitor);

        //清除函数，（events，pipewriter，loop）
        virtual void teardown();

        //保存订阅者信息的内部结构体
        typedef struct SubscriptionResult {
            ResponseStatus status;
            std::optional<ClientId> cid;
            std::optional<EventIds> events;
            std::optional<std::shared_ptr<SubsrciptionCallback>> sub_cb_;
        
            explicit SubscriptionResult(ResponseStatus status_in) : status(status_in) {}

            explicit SubscriptionResult(
                ResponseStatus status_in,
                ClientId cid_in,
                EventIds events_in,
                std::shared_ptr<SubsrciptionCallback> cb_in
            ) : status(status_in), cid(cid_in), events(events_in), sub_cb_(cb_in) {}
        } SubscriptionResult ;

        /**
         * @brief 增加订阅者集合
         * @param requested_events 订阅者集合
         * @return SubscriptionResult状态
         */
        SubscriptionResult acceptSubscription(const EventIds& requested_events);

        /**
         * @brief 取消订阅者的回调函数
         * @param cid 订阅者id
         */
        void onClientCanceled(ClientId cid) override;

        /**
         * @brief 订阅者订阅事件回调函数
         * @param cid 订阅者id
         * @param sub 订阅者
         * @param subscribed_events 订阅的事件集合
         */
        bool onClientSubscribed(
            ClientId cid,
            std::shared_ptr<ClientSubscriptionIf> sub,
            const EventIds& subscribed_events 
        ) override;

        bool initialized() {
            return initialized_;
        }

        //不是线程安全的，没有设置锁
        void set_limit(ClientId limit) {
            size_t size = subscription_map_.rlock()->size();
            if(limit >= size) {
                client_limit = limit;
            }
        }

        bool has_Client(ClientId cid) {
            auto sub = subscription_map_.rlock();
            auto it = sub->find(cid);
            return it != sub->end();
        }


    protected:
        /**
         * @brief 获取订阅者集合, 内部函数
         * @param eventid 事件id
         * @return 订阅者集合
         */
        ClientSubscriptionMap getSubscriptionMapForEvent(EventId eventid);

        /**
         * @brief 添加订阅者集合, 内部函数
         * @param cid 订阅者id
         * @param sub 订阅者
         * @param subscribed_events 订阅的事件集合
         */
        bool addSubscription(
            ClientId cid,
            std::shared_ptr<ClientSubscriptionIf> sub,
            const EventIds& subscribed_events
        );

        /**
         * @brief 取消订阅者集合, 内部函数
         * @param cid 订阅者id
         */
        void cancelSubscription(ClientId cid);

        bool initialized_ {false};

        std::shared_ptr<czkatranMonitor> monitor_ {nullptr};

        // 订阅者集合
        folly::Synchronized<ClientSubscriptionMap> subscription_map_;

        //当前的客户端id
        folly::Synchronized<ClientId> curr_id {0};

        //禁止的用户id
        ClientId client_limit {KDefaultClientLimit};

        // 当前启用的事件集合
        EventIds enabled_events_ ;

        // 客户端id到事件id的映射
        std::unordered_map<ClientId, std::set<EventId>> Client_to_EventIds_;

        /// EventId对应map的映射
        std::unordered_map<EventId, folly::AsyncPipeReader::UniquePtr> readers_;

        std::unordered_map<EventId, std::shared_ptr<folly::AsyncPipeWriter>> writers_;
        //事件回调函数
        std::unordered_map<EventId, std::unique_ptr<EventPipeCallback>> Events_to_cbs_;

        //读取线程
        folly::ScopedEventBaseThread reader_thread_;
};



}








}
