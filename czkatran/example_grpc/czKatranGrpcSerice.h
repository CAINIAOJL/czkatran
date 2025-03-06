#pragma once

#include <memory>
#include <mutex>

#include <grpc++/grpc++.h>
#include "/home/jianglei/czkatran/czkatran/example_grpc/goclient/src/czKatranc/lb_czKatran/czkatran.grpc.pb.h"
#include "/home/jianglei/czkatran/czkatran/example_grpc/goclient/src/czKatranc/lb_czKatran/czkatran.pb.h"
#include "/home/jianglei/czkatran/czkatran/lib/czkatranLb.h"
#include "/home/jianglei/czkatran/czkatran/lib/czkatranLbStructs.h"
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

namespace lb {
namespace czkatran {

class czKatranGrpcService final : public czKatranService::Service {
public:
    czKatranGrpcService() = delete;

    explicit czKatranGrpcService(const ::czkatran::czKatranConfig& config);

    Status changeMac(ServerContext* context, const Mac* request, Bool* response) override;

    Status getMac(ServerContext* context, const Empty* request, Mac* response) override;

    Status addVip(ServerContext* context, const VipMeta* request, Bool* response) override;

    Status delVip(ServerContext* context, const Vip* request, Bool* response) override;

    Status getAllVips(ServerContext* context, const Empty* request, Vips* response) override;

    Status modifyVip(ServerContext* context, const VipMeta* request, Bool* response) override;

    Status modifyReal(ServerContext* context, const RealMeta* request, Bool* response) override;

    Status getVipFlags(ServerContext* context, const Vip* request, Flags* response) override;

    Status addRealForVip(ServerContext* context, const realForVip* request, Bool* response) override;

    Status delRealForVip(ServerContext* context, const realForVip* request, Bool* response) override;

    Status modifyRealsForVip(ServerContext* context, const ModifiedRealForVip* request, Bool* response) override;

    Status getRealsForVip(ServerContext* context, const Vip* request, Reals* response) override;

    Status modifyQuicRealsMapping(ServerContext* context, const ModifiedQuicReals* request, Bool* response) override;

    Status getQuicRealsMapping(ServerContext* context, const Empty* request, QuicReals* response) override;

    Status getStatsForVip(ServerContext* context, const Vip* request, Stats* response) override;

    Status getLruStats(ServerContext* context, const Empty* request, Stats* response) override;

    Status getLruMissStats(ServerContext* context, const Empty* request, Stats* response) override;

    Status getLruFailbackStats(ServerContext* context, const Empty* request, Stats* response) override;

    Status getIcmpTooBigStats(ServerContext* context, const Empty* request, Stats* response) override;

    Status addHealthcheckerDst(ServerContext* context, const Healthcheck* request, Bool* response) override;

    Status delHealthcheckerDst(ServerContext* context, const Somark* request, Bool* response) override;

    Status getHealthcheckersDst(ServerContext* context, const Empty* request, hcMap* response) override;
private:
    ::czkatran::czKatranLb lb_;
    std::mutex gaint_; //锁
    bool hcForwarding_;
};

}
}
