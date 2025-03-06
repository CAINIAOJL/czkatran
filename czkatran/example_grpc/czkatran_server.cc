#include <signal.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gflags/gflags.h>
#include <grpc++/grpc++.h>
#include <folly/Conv.h>
#include <folly/String.h>
#include <folly/io/async/EventBase.h>
#include <folly/init/Init.h>

#include "GrpcSingalHandler.h"
#include "czKatranGrpcSerice.h"
#include "/home/jianglei/czkatran/czkatran/lib/MacHelpers.h"


using grpc::Server;
using grpc::ServerBuilder;

DEFINE_string(server, "0.0.0.0:50051", "grpc server: ip + port");
DEFINE_string(interface, "ens33", "main interface");
DEFINE_string(hc_interface, "", "interface for healthchecking");
DEFINE_string(ipip_interface, "ipip0", "ipip(v4) encap interface");
DEFINE_string(ipip6_interface, "ipip6", "ip(v6)ip(v6) encap interface");
DEFINE_string(balancer_prog, "balancer.o", "path to balancer program bpf prog");
DEFINE_string(healthchecker_prog, "healthchecker.o", "path to healthchecker program bpf prog");
DEFINE_string(default_mac, "00:00:00:00:00:01", "mac address of default router");
DEFINE_int32(priority, 2307, "tc's priority for bpf progs");
DEFINE_string(map_path, "", "path to pinned map from root xdp prog");
DEFINE_int32(prog_pos, 2, "czkatran's position inside root xdp array");
DEFINE_bool(hc_forwarding, true, "turn on forwarding path for healthchecking");
DEFINE_int32(shutdown_delay, 10000, "shutdown delay in milliseconds");
DEFINE_int64(lru_size, 80000000, "size of LRU table");
DEFINE_string(forwarding_cores, "", "comma separed list of forwarding cores");
DEFINE_string(numa_nodes, "", "comma separed list of numa nodes to forwarding cores mapping");

std::vector<int32_t> parseIntLine(const std::string& line) {
    std::vector<int32_t> nums;
    if(!line.empty()) {
        std::vector<std::string> splitedLine;
        folly::split(",", line, splitedLine); //分割函数
        for(const auto& num_str : splitedLine) {
            auto num = folly::to<int32_t>(num_str);
            nums.push_back(num);
        }
    }
    return nums;
}

void RunServer(czkatran::czKatranConfig& config, int32_t delay, std::shared_ptr<folly::EventBase> evb) 
{
    std::string server_address(FLAGS_server);
    lb::czkatran::czKatranGrpcService service(config);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    lb::czkatran::GrpcSignalHandler grpcSigHandler(evb, server.get(), delay);
    grpcSigHandler.registerSignalHandler(SIGINT);
    grpcSigHandler.registerSignalHandler(SIGTERM);

    server->Wait();
}



int main(int argc, char** argv) {
    folly::init(&argc, &argv);
    FLAGS_logtostderr = 1;

    auto forwardingCores = parseIntLine(FLAGS_forwarding_cores);
    VLOG(2) << "size of forwarding cores vector is " << forwardingCores.size();
    auto numaNodes = parseIntLine(FLAGS_numa_nodes);
    VLOG(2) << "size of numa nodes vector is " << numaNodes.size();

    czkatran::czKatranConfig config = {
        .mainInterface = FLAGS_interface,
        .v4TunInterface = FLAGS_ipip_interface,
        .v6TunInterface = FLAGS_ipip6_interface,
        .balancerProgPath = FLAGS_balancer_prog,
        .healthcheckingProgPath = FLAGS_healthchecker_prog,
        .defaultMac = czkatran::convertMacToUint(FLAGS_default_mac),
        .priority = static_cast<uint32_t>(FLAGS_priority),
        .rootMapPath = FLAGS_map_path,
        .rootMapPos = static_cast<uint32_t>(FLAGS_prog_pos),
        .enableHc = FLAGS_hc_forwarding
    };
    config.LruSize = static_cast<uint64_t>(FLAGS_lru_size);
    config.forwardingCores = forwardingCores;
    config.numaNodes = numaNodes;
    config.hcInterface = FLAGS_hc_interface;
    config.hashFunction = czkatran::HashFunction::Maglev2;

    auto evb = std::make_shared<folly::EventBase>();

    std::thread t1([evb](){
        evb->loopForever();
    });

    t1.detach();

    RunServer(config, FLAGS_shutdown_delay, evb);
    return 0;
}