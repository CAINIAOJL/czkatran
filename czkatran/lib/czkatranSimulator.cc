#include "czkatranSimulator.h"
//------------------------------------2025-2-15-------------------------------
//--------------------------√
#include <folly/IPAddress.h>
#include <glog/logging.h>
#include <cstring>

#include "BpfAdapter.h"

extern "C" {
    #include <linux/ipv6.h>
    #include <netinet/if_ether.h>
    #include <netinet/ip.h>
    #include <netinet/udp.h>
}

namespace czkatran {
namespace {
    constexpr uint16_t kMaxXdpPcktSize = 4096;
    constexpr uint16_t kTestPacketSize = 512;
    constexpr int kTestRepeatCount = 1;
    constexpr uint8_t kDefaultTtl = 64;
    constexpr uint8_t kIPv6AddrSize = 16;
    constexpr folly::StringPiece kEmptyString = "";  
} //namespace

namespace {
    void createV4Packet(//--------------------------√
        const folly::IPAddress& src,
        const folly::IPAddress& dst,
        std::unique_ptr<folly::IOBuf>& buf,
        uint8_t proto,
        uint16_t size
    )
    {   
        //指针指向buf可写处
        auto ehdr = 
            reinterpret_cast<struct ethhdr*>(buf->writableData());
        auto iph = 
            reinterpret_cast<struct iphdr*>(buf->writableData() + sizeof(struct ethhdr));
    
        ehdr->h_proto = htons(ETH_P_IP);
        iph->ihl = 5;
        iph->version = 4,
        iph->tos = 0;
        iph->frag_off = 0;
        iph->protocol = proto;
        iph->ttl = kDefaultTtl;
        iph->tot_len = htons(size);
        iph->daddr = dst.asV4().toLong();
        iph->saddr = src.asV4().toLong();
        iph->check = 0;
    }

    void createV6Packet(//--------------------------√
        const folly::IPAddress& src,
        const folly::IPAddress& dst,
        std::unique_ptr<folly::IOBuf>& buf,
        uint8_t proto,
        uint16_t size)
    {
        auto ehdr = 
            reinterpret_cast<struct ethhdr*>(buf->writableData());
        auto iph = 
            reinterpret_cast<struct ipv6hdr*>(buf->writableData() + sizeof(struct ethhdr));

        ehdr->h_proto = htons(ETH_P_IPV6);
        iph->version = 6;
        iph->priority = 0;
        iph->nexthdr = proto;
        iph->payload_len = htons(size - sizeof(struct ipv6hdr));
        std::memset(iph->flow_lbl, 0, sizeof(iph->flow_lbl));
        iph->hop_limit = kDefaultTtl;
        std::memcpy(iph->saddr.s6_addr16, src.asV6().toBinary().data(), kIPv6AddrSize);
        std::memcpy(iph->daddr.s6_addr16, dst.asV6().toBinary().data(), kIPv6AddrSize);
    }

    void createTcpHeader(//--------------------------√
        std::unique_ptr<folly::IOBuf>& buf,
        uint16_t srcPort,
        uint16_t dstPort,
        uint16_t offset)
    {
        auto tcph = reinterpret_cast<struct tcphdr*>(buf->writableData() + offset);
        std::memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source = htons(srcPort);
        tcph->dest = htons(dstPort);
        tcph->syn = 1;
    }

    void createUdpHeader(//--------------------------√
        std::unique_ptr<folly::IOBuf>& buf,
        uint16_t srcPort,
        uint16_t dstPort,
        uint16_t offset,
        uint16_t size)
    {
        auto udph = reinterpret_cast<struct udphdr*>(buf->writableData() + offset);
        std::memset(udph, 0, sizeof(struct udphdr));
        udph->source = htons(srcPort);
        udph->dest = htons(dstPort);
        udph->len = size;
    }
//------------------------------------2025-2-15-------------------------------
//--------------------------√

//------------------------------------2025-2-16-------------------------------

const std::string toV4String(uint32_t ip) {//--------------------------√
    return folly::IPAddressV4::fromLong(ip).str();
}

const std::string toV6String(uint8_t const* ipv6) {//--------------------------√
    folly::ByteRange bytes(ipv6, kIPv6AddrSize);
    return folly::IPAddressV6::fromBinary(bytes).str();
}


std::string getPcktDst(std::unique_ptr<folly::IOBuf>& pckt) {//--------------------------√
    if(pckt->computeChainDataLength() < sizeof(struct ethhdr)) {
        LOG(ERROR) << "result pckt is too short, less than ethhdr";
        return kEmptyString.data();
    }

    const struct ethhdr* ehdr = 
        reinterpret_cast<const struct ethhdr*>(pckt->data());
        if(ehdr->h_proto == htonl(ETH_P_IP)) {
            if(pckt->computeChainDataLength() < (sizeof(struct ethhdr) + sizeof(struct iphdr))) {
                LOG(ERROR) << "result pckt is too short, less than iphdr";
                return kEmptyString.data();
            }
            const struct iphdr* iph = 
                reinterpret_cast<const struct iphdr*>(pckt->data() + sizeof(struct ethhdr));
            return toV4String(iph->daddr);
        } else {
            if(pckt->computeChainDataLength() < (sizeof(struct ethhdr) + sizeof(struct ipv6hdr))) {
                LOG(ERROR) << "result pckt is too short, less than ipv6hdr";
                return kEmptyString.data();
            }
            const struct ipv6hdr* iph = 
                reinterpret_cast<const struct ipv6hdr*>(pckt->data() + sizeof(struct ethhdr));
            return toV6String(iph->daddr.s6_addr);
        }
}

//通过flow五元组，构造数据包
std::unique_ptr<folly::IOBuf> createPacketFromFlow(const czkatranFlow& flow)//--------------------------√
{
    int offset = sizeof(struct ethhdr);
    bool is_tcp = true;
    bool is_ipv4 = true;
    size_t l3hdr_len; //l3层长度

    auto srcExp = folly::IPAddress::tryFromString(flow.src);
    auto dstExp = folly::IPAddress::tryFromString(flow.dst);

    if(srcExp.hasError() || dstExp.hasError()) {
        LOG(ERROR) << fmt::format(
            "failed to format flow src: {}, dst: {} to IPAddress",
            flow.src,
            flow.dst
        );
        return nullptr;
    }

    auto src = srcExp.value();
    auto dst = dstExp.value();

    if(src.family() != dst.family()) {
        LOG(ERROR) << "src and dst family not match";
        return nullptr;
    }

    auto pckt = folly::IOBuf::create(kMaxXdpPcktSize);
    if(!pckt) {
        LOG(ERROR) << "failed to create packet";
        return pckt;
    }
    if(src.family() == AF_INET) {
        l3hdr_len = sizeof(struct iphdr);
    } else {
        l3hdr_len = sizeof(struct ipv6hdr);
    }

    offset += l3hdr_len;
    switch(flow.proto) {
        case IPPROTO_TCP:
            break;
        case IPPROTO_UDP:
            is_tcp = false;
            break;
        default:
            LOG(ERROR) << fmt::format("unsupported protocol: {}", flow.proto);
            return nullptr;
    }
    pckt->append(kTestPacketSize);
    auto playload_len = kTestPacketSize - sizeof(struct ethhdr);
    if(is_ipv4) {
        createV4Packet(src, dst, pckt, flow.proto, playload_len);
    } else {
        createV6Packet(src, dst, pckt, flow.proto, playload_len);
    }
    playload_len -= l3hdr_len; 
    if(is_tcp) {
        createTcpHeader(pckt, flow.srcport, flow.dstport, offset);
    } else {
        createUdpHeader(pckt, flow.srcport, flow.dstport, offset, playload_len);
    }
    return pckt;
}

} //namespace
//------------------------------------2025-2-16-------------------------------

czkatranSimulator::czkatranSimulator(int progfd) : prog_fd(prog_fd) {//--------------------------√
    affinitizeSimulatorThread();
}

czkatranSimulator::~czkatranSimulator() {}//--------------------------√

//git clone https://github.com/abseil/abseil-cpp.git
std::unique_ptr<folly::IOBuf> czkatranSimulator::runSimulation(//--------------------------√
    std::unique_ptr<folly::IOBuf> pckt
)
{
    std::unique_ptr<folly::IOBuf> result;
    //尽量使用lambda表达式，而不是是std::bind
    simulatorEvn_.getEventBase()->runInEventBaseThreadAndWait([&](){
        result = /*this.*/runSimulationInternal(std::move(pckt));
    });
    return result;
}

std::unique_ptr<folly::IOBuf> czkatranSimulator:: runSimulationInternal(
    std::unique_ptr<folly::IOBuf> pckt
)//--------------------------√
{
    //检查
    CHECK(simulatorEvn_.getEventBase()->isInEventBaseThread());
    if(!pckt) {
        LOG(ERROR) << "packet is null";
        return nullptr;
    }
    if(pckt->isChained()) {
        LOG(ERROR) << "packet is chained";
        return nullptr;
    }

    if(pckt->length() > kMaxXdpPcktSize) {
        LOG(ERROR) << "packet is too long";
        return nullptr;
    }
    auto rpckt = folly::IOBuf::create(kMaxXdpPcktSize);

    if(!rpckt) {
        LOG(ERROR) << "create rpckt failed";
        return rpckt;
    }

    uint32_t output_pckt_size {0};
    uint32_t prog_ret_val {0};
    auto res = BpfAdapter::textXdpProg(
        prog_fd,
        kTestRepeatCount,
        pckt->writableData(),
        pckt->length(),
        rpckt->writableData(),
        &output_pckt_size,
        &prog_ret_val
    );

    if(res < 0) {
        LOG(ERROR) << "textXdpProg failed";
        return nullptr;
    }

    if(prog_ret_val != XDP_TX) {
        LOG(ERROR) << "prog_ret_val is not XDP_TX";
        return nullptr;
    }
    rpckt->append(output_pckt_size); //?
    return rpckt;
}

const std::string czkatranSimulator::getRealForFlow(const czkatranFlow& flow) //--------------------------√
{
    auto pckt = createPacketFromFlow(flow);
    if(!pckt) {
        return kEmptyString.data();// ""
    }
    auto rpckt = runSimulation(std::move(pckt));
    if(!rpckt) {
        return kEmptyString.data();
    }
    return getPcktDst(rpckt);
}

void czkatranSimulator::affinitizeSimulatorThread()//--------------------------√
{
    simulatorEvn_.getEventBase()->runInEventBaseThreadAndWait([](){
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset); //设定cpu0
        pthread_t current_thread = pthread_self(); //当前线程
        auto ret = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
        if(ret != 0) {
            LOG(ERROR) << "pthread_setaffinity_np cpu0 failed" << "errno is " << errno;
        }
    });
}

//------------------------------------2025-2-15-------------------------------
//--------------------------√

}