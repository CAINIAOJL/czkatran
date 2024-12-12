#关于ipip协议的脚本
#实验：
## 用来创建tun1设备，并ipip协议的外层ip，目的ip为172.16.5.127， 源ip为172.16.5.126

ip tunnel add tun1 mode ipip remote 172.16.5.127 local 172.16.5.126
echo "tun1 created"
ip addr add 10.10.100.10 peer 10.10.200.10 dev tun1
ip link set tun1 up
echo "tun1 ip set success"
#wsl2缺少功能，无法测试tun1的ipip协议