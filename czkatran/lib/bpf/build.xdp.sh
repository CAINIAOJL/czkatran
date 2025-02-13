clang -D__KERNEL__ -Wno-unused-value -Wvisibility -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wvisibility -Wincompatible-pointer-types -O2 -emit-llvm -c -g  balancer.bpf.c -o -| llc -march=bpf -filetype=obj -o balancer.o
sudo ip link set dev lo xdpgeneric obj balancer.o sec xdp




clang -D__KERNEL__ -DINLINE_DECAP_IPIP -DICMP_TOOBIG_GENERATION -DUDP_STABLE_ROUTING -DTCP_SERVER_ID_ROUTING -DGLOBAL_LRU_LOOKUP -DLOCAL_DELIVERY_OPTIMIZATION -O2 -emit-llvm -c -g  balancer.bpf.c -o -| llc -march=bpf -filetype=obj -o balancer.o

clang -D__KERNEL__ -DINLINE_DECAP_GENERIC -DINLINE_DECAP_IPIP -DINLINE_DECAP_GUE -DICMP_TOOBIG_GENERATION -DUDP_STABLE_ROUTING -DTCP_SERVER_ID_ROUTING -DGLOBAL_LRU_LOOKUP -DLOCAL_DELIVERY_OPTIMIZATION  -O2 -emit-llvm -c -g balancer.bpf.c -o -| llc -march=bpf -filetype=obj -o balancer.o