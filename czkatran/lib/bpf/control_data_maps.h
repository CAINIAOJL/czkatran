#ifndef __CONTROL_DATA_MAPS_H__
#define __CONTROL_DATA_MAPS_H__


#if defined(GUE_ENCAP) || defined(DECAP_STRICT_DESTINATION) 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct real_definition);
} packet_srcs SEC(".maps");
#endif




#endif