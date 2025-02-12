clang -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o
sudo ip link set dev lo xdpgeneric obj decap_kern.o sec xdp
sudo xdp-loader status lo
sudo ip link set dev lo xdpgeneric off

clang -D__KERNEL__ -DINLINE_DECAP_GUE -DSERVER_ID_HASH_MAP -DDECAP_STRICT_DESTINATION -DTCP_HDR_OPT_SKIP_UNROLL_LOOP -DTCP_SERVER_ID_ROUTING -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o
