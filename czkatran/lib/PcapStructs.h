#pragma once


namespace czkatran {

/*
magic_number：用于检测文件格式本身和字节顺序。写入应用程序将具有本机字节排序格式0xa1b2c3d4写入此字段。
读取应用程序将读取 0xa1b2c3d4 （相同） 或 0xd4c3b2a1 （交换）。如果读取应用程序读取交换的 0xd4c3b2a1 值，则它知道以下所有字段也必须交换。

version_major、version_minor：该文件格式的版本号（当前版本为 2.4）

thisZone：GMT （UTC） 与以下数据包标头时间戳的本地时区之间的校正时间（以秒为单位）。
示例：如果时间戳采用 GMT （UTC） 格式，则 thiszone 只是 0。如果时间戳采用中欧时间（阿姆斯特丹、柏林等），即 GMT + 1：00，则此区域必须为 -3600。在实践中，时间戳始终采用 GMT 格式，因此 thiszone 始终为 0。

SIGFIGS：理论上，捕获中时间戳的准确性;在实践中，所有工具都将其设置为 0

snaplen：捕获的“快照长度”（通常为 65535 甚至更大，但可能会受到用户的限制），
请参阅下面的 incl_len 与 orig_len

network：链路层标头类型，指定数据包开头的标头类型
（例如，1 表示以太网，有关详细信息，请参阅 tcpdump.org 的链路层标头类型页面）;这可以是各种类型，
例如具有各种无线电信息的 802.11、802.11、PPP、令牌环、FDDI 等

*/


struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

/*
ts_sec：捕获此数据包的日期和时间。此值以秒为单位，自 1970 年 1 月 1 日 00：00：00 GMT 以来;这也称为 UN*X time_t。
您可以使用 time.h 中的 ANSI C time（） 函数来获取此值，但您可以使用更优化的方式来获取此时间戳值。
如果此时间戳不是基于 GMT （UTC），请使用全局标头中的 thiszone 进行调整。

ts_usec：在常规 pcap 文件中，为捕获此数据包时的微秒数，作为 ts_sec 的偏移量。
在纳秒级文件中，这是捕获数据包时的纳秒级，作为ts_sec ⚠️的偏移量请注意：此值不应达到 1 秒（在常规 pcap 文件中为 1 000 000;在纳秒级文件中为 1 000 000 000）;
在这种情况下，必须增加 ts_sec！

incl_len：文件中实际捕获并保存的数据包数据的字节数。
此值不应大于 orig_len 或全局标头的 snaplen 值。

orig_len：捕获数据包时数据包在网络上显示的长度。
如果 incl_len 和 orig_len 不同，则实际保存的数据包大小受 snaplen 的限制。
*/

struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

}