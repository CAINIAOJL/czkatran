clang -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o
sudo ip link set dev lo xdpgeneric obj decap_kern.o sec xdp
sudo xdp-loader status lo
sudo ip link set dev lo xdpgeneric off

clang -D__KERNEL__ -DINLINE_DECAP_GUE -DSERVER_ID_HASH_MAP -DDECAP_STRICT_DESTINATION -DTCP_HDR_OPT_SKIP_UNROLL_LOOP -DTCP_SERVER_ID_ROUTING -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o

#decap_stpict_destination
-DDECAP_STRICT_DESTINATION

#inline_decap_gue
-DINLINE_DECAP_GUE

#tcp_server_id_routing
-DTCP_SERVER_ID_ROUTING

#decap_tpr_stats
-DDECAP_TPR_STATS

#tcp_hdr_opt_skip_unroll_loop
-DTCP_HDR_OPT_SKIP_UNROLL_LOOP

#if defined(TCP_SERVER_ID_ROUTING) || defined(DECAP_TPR_STATS)
-DTCP_SERVER_ID_ROUTING

-DDECAP_TPR_STATS

clang -D__KERNEL__ -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o