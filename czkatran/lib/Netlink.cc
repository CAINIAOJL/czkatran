#include "Netlink.h"

#include <libmnl/libmnl.h> 
#include <array>
#include <cstring>
extern "C" {
    #include <arpa/inet.h>
    #include <arpa/inet.h>
    #include <linux/if_ether.h>
    //Rtnetlink 允许对内核路由表进行读和更改，它用于内核与各个子系统之间（路由子系统、IP地址、链接参数等）的通信，
    #include <linux/rtnetlink.h>
    //linux中TC
    #include <linux/tc_act/tc_gact.h>
}

/*
TC_ACT_UNSPEC（-1）: 使用tc 命令所配置的 action（和classifier相类似）。
TC_ACT_OK（0）: 放行，结束整个处理流程（processing pipeline），虽然未实际验证，这里暗示的应该是后续的filter都不会被经过。
TC_ACT_RECLASSIFY（1）： 结束处理流程，重新classification，未实际验证，不过猜想的场景是直接修改了packet的数据然后在去进行分类。
TC_ACT_SHOT（2）：结束处理流程并且将packet丢弃
TC_ACT_PIPE（3）：去往下一个action，如果存在的话。
*/

/*
TCA_UNSPEC：未指定的值，通常用作默认或无效选项的占位符。
TCA_KIND：指定流量控制调度器或类的类型。例如，它可以是pfifo_fast、htb（Hierarchical Token Bucket）等。
TCA_OPTIONS：指定与特定流量控制实体相关的配置选项。这些选项依赖于TCA_KIND指定的调度器或类类型。
TCA_STATS：提供流量控制实体的统计信息，如发送/接收的数据包数量、字节数等。
TCA_XSTATS：扩展统计信息，提供比TCA_STATS更详细或特定于实现的统计信息。
TCA_RATE：指定或查询流量速率限制。
TCA_FCNT：流量计数器，可能用于跟踪经过特定流量控制点的数据包数量。
TCA_STATS2：提供比TCA_STATS更丰富的统计信息，可能包含更多细节或不同格式的统计数据。
TCA_STAB：速率表（Rate Table），用于定义与速率相关的参数，如令牌桶算法中的速率和突发大小。
TCA_PAD：填充值，用于确保枚举值的对齐或满足特定的数据结构要求。
TCA_DUMP_INVISIBLE：在导出或“转储”流量控制配置时，包括那些通常不可见的实体。
TCA_CHAIN：指定或查询流量控制链，即一系列相互关联的调度器或类。
TCA_HW_OFFLOAD：指示流量控制操作是否可以被硬件卸载，即是否可以由网络设备直接处理，而不是由软件处理。
TCA_INGRESS_BLOCK：指定或查询入站流量控制块，用于处理进入网络接口的数据包。
TCA_EGRESS_BLOCK：指定或查询出站流量控制块，用于处理从网络接口发送的数据包。
TCA_DUMP_FLAGS：在导出流量控制配置时使用的标志，可能用于控制输出的格式或内容。
TCA_EXT_WARN_MSG：扩展警告消息，可能用于提供关于配置错误或不支持的选项的额外信息。
__TCA_MAX：这是一个特殊的枚举值，通常用于表示枚举列表中有效值的数量。它本身不对应任何有效的流量控制属性或选项，但可以用于循环或数组大小的计算。
这些枚举值在Linux内核的流量控制子系统中非常有用，特别是在配置和管理网络接口的队列规则、调度器和类时。
*/




#ifndef TCA_BPF_FLAGS_ACT_DIRECT
#define TCA_BPF_FLAGS_ACT_DIRECT (1 << 0) 
#endif

//不太清楚TC层实现原理
namespace {
    std::array<const char, 4> kBpfKind = {"bpf"};
    std::array<const char, 5> kTcActkind = {"gact"};
    std::array<const char, 7> kClsactkind = {"clsact"}; 
    constexpr unsigned TCA_BPF_PRIO_1 = 1;
}// namespace


namespace czkatran {

NetlinkMessage::NetlinkMessage(): data_(MNL_SOCKET_BUFFER_SIZE) {}


/**
    format of netlink msg:
    +-------------------------------+
    |type                           |        （1）
    +-------------------------------+
    |flags                          |        （2）
    +-------------------------------+
    |seq                            |        （3）
    +-------------------------------+
    |##### TC's header #####        |        （4）
    +-------------------------------+
    |family                         |        （5）  
    +-------------------------------+
    |ifindex                        |        （6）
    +-------------------------------+
    |parent                         |        （7）
    +-------------------------------+
    |tcm_info                       |        （8）
    +-------------------------------+
    |TCA_KIND                       |        （9）
    +-------------------------------+
    |TCA_options (nested)           |        （10）
    +-------------------------------+
    |bpf prog fd                    |        （11）
    +-------------------------------+
    |bpf flags                      |        （12）
    +-------------------------------+
    |bpf name                       |        （13）
    +-------------------------------+
    |TCA bpf act (nested)           |        （14）
    +-------------------------------+
    |TCA bpf prio (nested)          |        （15）
    +-------------------------------+
    |TCA act  kind                  |        （16）
    +-------------------------------+
    |TCA act options (nested)       |        （17）
    +-------------------------------+
    |TCA gact params                |        （18）
    +-------------------------------+
    |end of TCA act options         |        （19）
    +-------------------------------+
    |end of TCA bpf prio            |        （20）
    +-------------------------------+
    |end of TCA bpf act             |        （21）        
    +-------------------------------+ 
    |end of TCA options             |        （22）
    +-------------------------------+

    netlink's header:

    1) type: depends of command, add/delete/modify filter (actual constanst in
       helpers above)
    2) flags: depends of the type; could be create/ create + exclusive / 0 (in
       case of delitation)
    3) seq - seq number for this message, we are going to use cur time in sec

    tc related headers and fields:
    1) family: either 0 for deletation or ETH_P_ALL if we are adding new
    filter 2) ifindex: index of interface where we are going to attach our
    prog. 3) parent: for bpf this field indicates the direction of the filter.
       either ingress or egress.
    4) tcm_info: for tc's filter this field combines protocol and priority
       (rfc3549 3.1.3)
    5) TCA_KIND: for bpf it's "bpf"
    bpf's specific options:
    1) bpf_prog_fd: file descriptor of already loaded bpf program
    2) bpf_flags: bpf related flags; for our use case use are using
       "direct action" (for imediate return after BPF run)
    3) bpf_name: name of bpf prog (to identify it, e.g. in tc show output), no
       special meaning behind this.
    4) act_kind: for bpf's related filter it's fixed to "gact"
    5) gact params: we only specify default action as TC_ACT_OK (we are going
       to hit this only if bpf prog exits w/ TC_ACT_PIPE and there is not
    filter after it)

  */

NetlinkMessage NetlinkMessage:: TC(unsigned seq,
                            int cmd,
                            unsigned flags,
                            uint32_t priority,
                            int prog_fd,
                            unsigned ifindex,
                            const std::string& bpf_name,
                            int dirction,
                            const uint32_t handle) {

    NetlinkMessage ret;
    unsigned char* buf = ret.data_.data();

    struct nlmsghdr* hdr; //Netlink message header;
    struct tcmsg* tcm; //tc message header;
    uint32_t  protocol = 0;
    unsigned int bpfFlags = TCA_BPF_FLAGS_ACT_DIRECT;

    //创建Netlink消息头
    hdr = mnl_nlmsg_put_header(buf);
    hdr->nlmsg_seq = seq;                                                                              //---------------（3）
    hdr->nlmsg_type = cmd;                                                                             //---------------（1）
    hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;                                              //---------------（2）  

    //创建TC消息头
    tcm = reinterpret_cast<struct tcmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(struct tcmsg)));  //---------------（4）
    tcm->tcm_family = AF_UNSPEC;                                                                       //----------------（5）
    tcm->tcm_ifindex = ifindex;                                                                        //----------------（6）
    tcm->tcm_parent = dirction;                                                                        //----------------（7）
    tcm->tcm_handle = TC_H_MAKE(0, handle);

    //cmd: create a new filter 创建一个过滤器
    if(cmd == RTM_NEWTFILTER && flags & NLM_F_CREATE) {
        protocol = htons(ETH_P_ALL);
    }
    
    tcm->tcm_info = TC_H_MAKE(priority << 16, protocol);                                               //----------------（8）
    //TLV = Tag Length Value 编码格式 TLV编码是一种广泛用于通信协议和数据交换的编码方式
    //觉得意思为将TVL数据编码放入到nlmsghdr中
    mnl_attr_put(hdr, TCA_KIND, kBpfKind.size(), kBpfKind.data());                      //-----------------（9）
    {
      //TLV attribute nesting 嵌套TLV属性
      struct nlattr* options = mnl_attr_nest_start(hdr, TCA_OPTIONS);                       //------------------(10)
      mnl_attr_put_u32(hdr, ::TCA_BPF_FD, prog_fd);                                   //------------------(11)
      mnl_attr_put_u32(hdr, ::TCA_BPF_FLAGS, bpfFlags);                               //------------------(12)
      mnl_attr_put(hdr, ::TCA_BPF_NAME, bpf_name.size() + 1, bpf_name.c_str());  //-------------------(13)
      {
         struct nlattr* act = mnl_attr_nest_start(hdr, ::TCA_BPF_ACT);                     //-------------------(14)
         {
            struct nlattr* prio = mnl_attr_nest_start(hdr, TCA_BPF_PRIO_1);                //-------------------(15)
            mnl_attr_put(hdr, ::TCA_ACT_KIND, kTcActkind.size(), kTcActkind.data());  //-------------------(16)
            {
               struct nlattr* actOptions = mnl_attr_nest_start(hdr, ::TCA_ACT_OPTIONS);  //---------------------(17)
               struct tc_gact gactparams;
               memset(&gactparams, 0, sizeof(gactparams));
               gactparams.action = TC_ACT_OK;
               mnl_attr_put(hdr, ::TCA_GACT_PARMS, sizeof(gactparams), &gactparams);  //--------------(18)
               mnl_attr_nest_end(hdr, actOptions);                                             //--------------(19)
            }
            mnl_attr_nest_end(hdr, prio);                                                      //--------------(20) 
         }
         mnl_attr_nest_end(hdr, act);                                                         //---------------(21)
      }
      mnl_attr_nest_end(hdr, options);                                                        //---------------(22)
    }
    //定义消息长度
    ret.data_.resize(hdr->nlmsg_len);
    return ret;
}

NetlinkMessage NetlinkMessage::QD(unsigned ifindex) {
   NetlinkMessage ret;
   unsigned char* buf = ret.data_.data();

   struct nlmsghdr* hdr; //Netlink message header;
   struct tcmsg* tcm; //tc message header;

   hdr = mnl_nlmsg_put_header(buf);
   hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
   hdr->nlmsg_type = RTM_NEWQDISC;

   tcm = reinterpret_cast<struct tcmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(struct tcmsg)));
   tcm->tcm_family = AF_UNSPEC;
   tcm->tcm_ifindex = ifindex;
   tcm->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0); //clsact的handle
   tcm->tcm_parent = TC_H_CLSACT;

   mnl_attr_put(hdr, TCA_KIND, kClsactkind.size(), kClsactkind.data());
   ret.data_.resize(hdr->nlmsg_len);
   return ret;
}

NetlinkMessage NetlinkMessage::XDP(unsigned seq,
                             int prog_fd,
                             unsigned ifindex,
                             uint32_t flags) {
   NetlinkMessage ret;
   unsigned char* buf = ret.data_.data();

   struct nlmsghdr* hdr; //Netlink message header;
   struct ifinfomsg* ifinfo; //Link layer specific messages.

   hdr = mnl_nlmsg_put_header(buf);
   hdr->nlmsg_seq = seq;
   hdr->nlmsg_type = RTM_NEWLINK;
   hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
   
   ifinfo = reinterpret_cast<struct ifinfomsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(struct ifinfomsg)));
   ifinfo->ifi_family = AF_UNSPEC;
   ifinfo->ifi_index = ifindex;

   {
      struct nlattr* xdp_atr = mnl_attr_nest_start(hdr, IFLA_XDP);
      mnl_attr_put_u32(hdr, IFLA_XDP_FD, prog_fd);
      if(flags > 0) {
         mnl_attr_put_u32(hdr, IFLA_XDP_FLAGS, flags);
      }
      mnl_attr_nest_end(hdr, xdp_atr);
   }

   ret.data_.resize(hdr->nlmsg_len);
   return ret;
}

unsigned NetlinkMessage:: seq() const {
   const struct nlmsghdr* hdr = reinterpret_cast<const struct nlmsghdr*>(data());
   return hdr->nlmsg_seq;
}

}