clang -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g bpf/decap.bpf.c -o -| llc -march=bpf -filetype=obj -o decap_kern.o
sudo ip link set dev lo xdpgeneric obj decap_kern.o sec xdp
sudo xdp-loader status lo
sudo ip link set dev lo xdpgeneric off