#include "czKatranGrpcSerice.h"

#include <glog/logging.h>

#include "/home/jianglei/czkatran/czkatran/lib/MacHelpers.h"
#include "/home/jianglei/czkatran/czkatran/lib/Vip.h" // Include the header for Vip class
#include "absl/time/time.h"
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

namespace lb {
namespace czkatran {
using Guard = std::lock_guard<std::mutex>; //加锁

::czkatran::VipKey transalteVipObject(const Vip& vip) {
    ::czkatran::VipKey key;
    key.address = vip.address();
    key.port = vip.port();
    key.proto = vip.protocol();
    return key;
}

::czkatran::NewReal transalteRealObject(const Real& real) {
    ::czkatran::NewReal nr;
    nr.address = real.address();
    nr.flags = real.flags();
    nr.weight = real.weight();
    return nr;
}

::czkatran::QuicReal transalteQuicRealObject(const QuicReal& quicReal) {
    ::czkatran::QuicReal nr;
    nr.address = quicReal.address();
    nr.id = quicReal.id();
    return nr;
}

Status retrunStatus(bool result) {
    if(result) {
        return Status::OK;
    } else {
        return Status::CANCELLED;
    }
}

czKatranGrpcService::czKatranGrpcService(const ::czkatran::czKatranConfig& config): lb_(config, std::make_unique<::czkatran::BpfAdapter>(config.memlockUnlimited)),hcForwarding_(config.enableHc) {
    lb_.loadBpfProgs();
    lb_.attachBpfProgs();
}

Status czKatranGrpcService:: changeMac(ServerContext* context, const Mac* request, Bool* response)
{
    Guard guard(gaint_);
    auto macint = ::czkatran::convertMacToUint(request->mac());
    auto res = lb_.changeMac(macint);
    response->set_success(res);
    return retrunStatus(res); //返回状态码
}

Status czKatranGrpcService:: getMac(ServerContext* context, const Empty* request, Mac* response)
{
    Guard guard(gaint_);
    auto macint = lb_.getMac();
    response->set_mac(::czkatran::convertMacToString(macint));
    return Status::OK;
}

Status czKatranGrpcService:: addVip(ServerContext* context, const VipMeta* request, Bool* response)
{
    bool res;
    auto vp = transalteVipObject(request->vip());
    try {
        Guard guard(gaint_);
        res = lb_.addVip(vp, request->flags());
    }catch (const std::exception& e) {
        LOG(INFO) << "Exception in addVip: " << e.what();
        res = false;
    }
    response->set_success(res);
    return  retrunStatus(res);
}

Status czKatranGrpcService:: delVip(ServerContext* context, const Vip* request, Bool* response)
{
    Guard guard(gaint_);
    auto vk = transalteVipObject(*request);
    auto res = lb_.delVip(vk);
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: getAllVips(ServerContext* context, const Empty* request, Vips* response)
{
    Guard guard(gaint_);
    Vip vp;
    auto vps = lb_.getAllVips();
    for(auto& v : vps) {
        vp.set_address(v.address);
        vp.set_port(v.port);
        vp.set_protocol(v.proto);
        auto rvp = response->add_vips();
        *rvp = vp;
    }
    return Status::OK;
}

Status czKatranGrpcService:: modifyVip(ServerContext* context, const VipMeta* request, Bool* response)
{
    Guard guard(gaint_);
    ::czkatran::VipKey vk = transalteVipObject(request->vip());
    auto res = lb_.modifyVip(vk, request->flags(), request->setflags());
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: modifyReal(ServerContext* context, const RealMeta* request, Bool* response)
{
    Guard guard(gaint_);
    auto res = lb_.modifyReal(request->real().address(), request->real().flags(), request->setflags());
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: getVipFlags(ServerContext* context, const Vip* request, Flags* response)
{   int64_t flags = -1;
    auto vk = transalteVipObject(*request); 
    try {
        Guard guard(gaint_);
        flags = lb_.getVipFlags(vk);
    }catch (const std::exception& e) {
        LOG(INFO) << "Exception in getVipFlags: " << e.what();
    }
    response->set_flags(flags);
    return Status::OK;
}

Status czKatranGrpcService:: addRealForVip(ServerContext* context, const realForVip* request, Bool* response)
{
    bool res;
    auto vk = transalteVipObject(request->vip());
    auto nr = transalteRealObject(request->real());

    try {
        Guard guard(gaint_);
        res = lb_.addRealForVip(nr, vk);
    } catch(const std::exception& e) {
        LOG(INFO) << "Exception in addRealForVip: " << e.what();
        res = false;
    }
    response->set_success(res);
    return retrunStatus(res);
}   

Status czKatranGrpcService:: delRealForVip(ServerContext* context, const realForVip* request, Bool* response)
{
    bool res;
    auto vk = transalteVipObject(request->vip());
    auto nr = transalteRealObject(request->real());
    Guard guard(gaint_);
    res = lb_.deleteRealForVip(nr, vk);
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: modifyRealsForVip(ServerContext* context, const ModifiedRealForVip* request, Bool* response)
{
    ::czkatran::ModifyAction a;
    std::vector<::czkatran::NewReal> upreals;
    switch(request->action()) {
        case ::czkatran::ModifyAction::ADD:
            a = ::czkatran::ModifyAction::ADD;
            break;
        case ::czkatran::ModifyAction::DEL:
            a = ::czkatran::ModifyAction::DEL;
            break;
        default:
            break;
    }
    auto vk = transalteVipObject(request->vip());
    for(int i = 0; i < request->real().reals_size(); i++) {
        auto nr = transalteRealObject(request->real().reals(i));
        upreals.push_back(nr);
    }
    bool res;
    try {
        Guard guard(gaint_);
        res = lb_.modifyRealsForVip(a, upreals, vk);
    }catch (const std::exception& e) {
        LOG(INFO) << "Exception in modifyRealsForVip: " << e.what();
        res = false;
    }
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: getRealsForVip(ServerContext* context, const Vip* request, Reals* response)
{
    auto vk = transalteVipObject(*request);
    std::vector<::czkatran::NewReal> reals;
    Real R;

    try {
        Guard guard(gaint_);
        reals = lb_.getRealsForVip(vk);
    } catch(const std::exception& e) {
        LOG(INFO) << "Exception in getRealsForVip: " << e.what();
        return Status::CANCELLED;
    }

    for(auto& r: reals) {
        R.set_address(r.address);
        R.set_flags(r.flags);
        R.set_weight(r.weight);
        auto rr = response->add_reals();
        *rr = R;
    }
    return Status::OK;
}

Status czKatranGrpcService:: modifyQuicRealsMapping(ServerContext* context, const ModifiedQuicReals* request, Bool* response)
{
    ::czkatran::ModifyAction a;
    std::vector<::czkatran::QuicReal> upreals;
    switch(request->action()) {
        case ::czkatran::ModifyAction::ADD:
            a = ::czkatran::ModifyAction::ADD;
            break;
        case ::czkatran::ModifyAction::DEL:
            a = ::czkatran::ModifyAction::DEL;
            break;
        default:
            break;
    }
    bool res;
    for(int i = 0; i < request->reals().quicreals_size(); i++) {
        auto qr = transalteQuicRealObject(request->reals().qreals(i));
        upreals.push_back(qr);
    }
    try {
        Guard guard(gaint_);
        lb_.modifyQuicRealsMapping(a, upreals);
    } catch (const std::exception& e) {
        LOG(INFO) << "Exception in modifyQuicRealsMapping: " << e.what();
        res = false;
    }
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: getQuicRealsMapping(ServerContext* context, const Empty* request, QuicReals* response)
{
    QuicReal qr;
    std::vector<::czkatran::QuicReal> qrs;
    try {
        Guard guard(gaint_);
        qrs = lb_.getQuicRealsMapping();
    }catch(const std::exception& e) {
        LOG(INFO) << "Exception in getQuicRealsMapping: " << e.what();
        return Status::CANCELLED;
    }

    for(auto& qreal : qrs) {
        qr.set_address(qreal.address);
        qr.set_id(qreal.id);
        auto qrr = response->add_qreals();
        *qrr = qr;
    }
    return Status::OK;
}

Status czKatranGrpcService:: getStatsForVip(ServerContext* context, const Vip* request, Stats* response)
{
    auto vk = transalteVipObject(*request);
    Guard guard(gaint_);
    auto s = lb_.getStatsForVip(vk);
    response->set_v1(s.v1);
    response->set_v2(s.v2);
    return Status::OK;
}

Status czKatranGrpcService:: getLruStats(ServerContext* context, const Empty* request, Stats* response)
{
    Guard guard(gaint_);
    auto s = lb_.getLruStats();
    response->set_v1(s.v1);
    response->set_v2(s.v2);
    return Status::OK;
}

Status czKatranGrpcService:: getLruMissStats(ServerContext* context, const Empty* request, Stats* response)
{
    Guard guard(gaint_);
    auto s = lb_.getLruMissStats();
    response->set_v1(s.v1);
    response->set_v2(s.v2);
    return Status::OK;
}

Status czKatranGrpcService:: getLruFailbackStats(ServerContext* context, const Empty* request, Stats* response)
{
    Guard guard(gaint_);
    auto s = lb_.getLruFallbackStats();
    response->set_v1(s.v1);
    response->set_v2(s.v2);
    return Status::OK;
}

Status czKatranGrpcService:: getIcmpTooBigStats(ServerContext* context, const Empty* request, Stats* response)
{
    Guard guard(gaint_);
    auto s = lb_.getIcmpTooBigStats();
    response->set_v1(s.v1);
    response->set_v2(s.v2);
    return Status::OK;
}

Status czKatranGrpcService:: addHealthcheckerDst(ServerContext* context, const Healthcheck* request, Bool* response)
{
    if(!hcForwarding_) {
        response->set_success(false);
        return Status::CANCELLED;
    }
    bool res;
    try {
        Guard guard(gaint_);
        res = lb_.addHealthcheckerDst(request->somark(), request->address());
    } catch (const std::exception& e) {
        LOG(INFO) << "Exception in addHealthcheckerDst: " << e.what();
        res = false;
    }
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: delHealthcheckerDst(ServerContext* context, const Somark* request, Bool* response)
{
    if(!hcForwarding_) {
        response->set_success(flase);
        return Status::CANCELLED;
    }
    bool res;
    Guard guard(gaint_);
    res = lb_.delHealthcheckerDst(request->somark());
    response->set_success(res);
    return retrunStatus(res);
}

Status czKatranGrpcService:: getHealthcheckersDst(ServerContext* context, const Empty* request, hcMap* response)
{
    if(!hcForwarding_) {
        return Status::CANCELLED;
    }
    Guard guard(gaint_);
    auto hcdsts = lb_.getHealthcheckersDst();
    auto rhcs = response->mutable_healthchecks();
    for(auto& hc : hcdsts) {
        (*rhcs)[hc.first] = hc.second;
    }
    return Status::OK;
}

}
}

