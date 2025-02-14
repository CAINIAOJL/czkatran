//------------------------------------2025-2-14-------------------------------
//--------------------------√
#include "czkatranTestProvision.h"
#include <glog/logging.h>
#include <map>
namespace czkatran {
namespace testing {

const std::string kMainInterface = "lo";
const std::string kV4TunInterface = "lo";
const std::string kV6TunInterface = "lo";
const std::string kNoExternalMap = "";

const std::vector<uint8_t> kDefalutMac = {0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF};
const std::vector<uint8_t> KLocalMac = {0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xAF};

const std::vector<std::string> kReals = {
    //ipv4
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    //ipv6
    "fc00::1",
    "fc00::2",
    "fc00::3",
};

const std::vector<::czkatran::lb_stats> kDefaultRealStats = {
    {0, 0},
    {9, 422},
    {5, 291},
    {4, 206},
    {2, 76},
    {3, 156},
};

const std::vector<::czkatran::lb_stats> kTPRRealStats = {
    {0, 0},
    {3, 181},
    {4, 244},
    {8, 356},
    {2, 134},
    {0, 0},
};

const std::map<TestMode, std::vector<::czkatran::lb_stats>> kRealsStats = {
    {TestMode::DEFAULT, kDefaultRealStats},
    {TestMode::GUE, kDefaultRealStats},
    {TestMode::TPR, kTPRRealStats}
};

void addReals(//--------------------------√
    czkatran::czKatranLb& lb,
    const czkatran::VipKey& vip,
    const std::vector<std::string>& reals //IpAddress 集合
)
{
    czkatran::NewReal real;
    real.weight = kDefaultWeight;
    for (auto& r : reals) {
        real.address = r;
        lb.addRealForVip(real, vip);
    }
}

void deleteReals(//--------------------------√
    czkatran::czKatranLb& lb,
    const czkatran::VipKey& vip,
    const std::vector<std::string>& reals //IpAddress 集合
)
{
    czkatran::NewReal real;
    real.weight = kDefaultWeight;
    for(auto& r : reals) {
        real.address = r;
        lb.deleteRealForVip(real, vip);
    }
}

void addQuicMappings(czkatran::czKatranLb& lb)//--------------------------√
{
    czkatran::QuicReal qreal;
    std::vector<czkatran::QuicReal> qreals;
    auto action = czkatran::ModifyAction::ADD;
    //6个
    std::vector<uint16_t> ids = {1022, 1023, 1025, 1024, 1026, 1027};
    for(int i = 0; i < 6; i++) {
        //CID V1
        qreal.address = kReals[i];
        qreal.id = ids[i];
        qreals.push_back(qreal);

        //CID V2
        qreal.address = kReals[i];
        constexpr uint32_t twJobMask = 0x030000;
        qreal.id = twJobMask | ids[i];
        qreals.push_back(qreal);

        LOG(INFO) << "Adding mapping for" << qreal.address << " with id = " << qreal.id;

        printf("%02X%02X%02X%02X\n",
                (qreal.id >> 24) & 0xFF,
                (qreal.id >> 16) & 0xFF,
                (qreal.id >> 8) & 0xFF,
                (qreal.id & 0xFF)); 
    }
    lb.modifyQuicRealsMapping(action, qreals);
}

void prepareLbData(czkatran::czKatranLb& lb)
{
    lb.restartczKatranMonitor(kMonitorLimit);
    czkatran::VipKey vip;
    //服务器端节点
    //一个vip对应一组reals
    std::vector<std::string> reals = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
    std::vector<std::string> reals6 = {"fc00::1", "fc00::2", "fc00::3"};

    vip.address = "10.200.1.1";
    vip.port = kVipPort;
    vip.proto = kUdp;

//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kUdp]---------//
    lb.addVip(vip);
    addReals(lb, vip, reals); //vip: udp >> reals
//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kUdp]---------//

//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kTcp]---------//
    vip.proto = kTcp;
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(udp)[address: 10.200.1.1, port: kVipPort, proto: kTcp]---------//

//-------vip(udp)[address: 10.200.1.2, port: 0, proto: kTcp]---------//
    vip.address = "10.200.1.2";
    vip.port = 0;
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(udp)[address: 10.200.1.2, port: 0, proto: kTcp]---------//

//-------vip(udp)[address: 10.200.1.4, port: 0, proto: kTcp]---------//
    vip.address = "10.200.1.4";
    lb.addVip(vip);
    addReals(lb, vip, reals);
//-------vip(udp)[address: 10.200.1.4, port: 0, proto: kTcp]---------//

//------------------------------------2025-2-14-------------------------------






}


}
}