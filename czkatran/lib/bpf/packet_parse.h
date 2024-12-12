#ifndef __PACKET_PARSE_H__
#define __PACKET_PARSE_H__

#include <linux/udp.h>


#include <bpf/bpf.h>
#include "czkatran/lib/bpf/balancer_consts.h"
#include "czkatran/lib/bpf/balancer_structs.h"


__always_inline static bool parse_udp(void *data,
                                      void *data_end,
                                      bool is_ipv6,
                                      struct packet_description *packet) {
    struct udphdr                                    






}




#endif