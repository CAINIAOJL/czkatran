#pragma once
#include <string>
#include <vector>
#include <utility>
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/PacketAttributes.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/PacketAttributes.h"
#include "PacketAttributes.h"
namespace czkatran {
namespace testing {
/**
 * see KatranTestFixtures.h on how to generate input and output data
 */
using TestFixture = std::vector<PacketAttributes>;
const TestFixture gueOptionalTestFixtures = {
  //1
  {
    // Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/("katran test pkt"*100)
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAX4AAEAAEARp4LAqAEBCsgBAXppAFAF5Og2a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0a2F0cmFuIHRlc3QgcGt0",
    .description = "ICMPv4 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AQAAAAAAAgAAAAAACABFAABwAAAAAEABrRsKyAEBwKgBAQMEboQAAAXcRQAF+AABAABAEaeCwKgBAQrIAQF6aQBQBeToNmthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0IHBrdGthdHJhbiB0ZXN0"
  },
  //2
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/("katran test pkt"*100)
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAABfAGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAFN1AABrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ICMPv6 packet too big. ICMP_TOOBIG_GENERATION and 4.17+ kernel is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AQAAAAAAAgAAAAAAht1gAAAAAQA6QPwAAAEAAAAAAAAAAAAAAAH8AAACAAAAAAAAAAAAAAABAgD3sgAABdxgAAAABfAGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAFN1AABrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdGVzdCBwa3RrYXRyYW4gdA=="
  },
  //3
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU/AqAEBCsgBAXppAFAAF5fea2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm cached flow. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA2h7F8AAMwAARQAAKwABAABAEa1PwKgBAQrIAQF6aQBQABeX3mthdHJhbiB0ZXN0IHBrdA=="
  },
  //4
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.1.2", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARrU7AqAECCsgBAXppAFAAF5fda2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm src lookup /17. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwABe2sXwAAzAABFAAArAAEAAEARrU7AqAECCsgBAXppAFAAF5fda2F0cmFuIHRlc3QgcGt0"
  },
  //5
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.100.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEARSk/AqGQBCsgBAXppAFAAFzTea2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm src lookup /24 . LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwACHmgXwAAzAABFAAArAAEAAEARSk/AqGQBCsgBAXppAFAAFzTea2F0cmFuIHRlc3QgcGt0"
  },
  //6
  {
    //Ether(src="0x1", dst="0x2")/IP(src="192.168.200.1", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAEAR5k7AqMgBCsgBAXppAFAAF9Dda2F0cmFuIHRlc3QgcGt0",
    .description = "ipv4: lpm miss. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAACABFAABHAAAAAEARWX8KAA0lCgAAA6F7F8AAMwAARQAAKwABAABAEeZOwKjIAQrIAQF6aQBQABfQ3WthdHJhbiB0ZXN0IHBrdA=="
  },
  //7
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1OAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm src lookup /64. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwAQemkXwABTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1OAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //8
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2307::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwcAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpKAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm src lookup /32. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwAEemkXwABTAABgAAAAACMGQPwAIwcAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpKAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //9
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2308:1::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAIwgAAQAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm miss. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAABemkXwABTAABgAAAAACMGQPwAIwgAAQAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //10
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="fc00:2::1", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "ipv6: lpm cached flow. LPM_SRC_LOOKUP is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAAAAADemkXwABTAABgAAAAACMGQPwAAAIAAAAAAAAAAAAAAAH8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgAP1PAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //11
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=6080)/IP(src="192.168.1.3", dst="10.200.1.1")/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkXwAAzKZJFAAArAAEAAEARrU3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0",
    .description = "gue ip4ip6 inline decap. INLINE_DECAP_GUE is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAADMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwABe2oXwAAzAABFAAArAAEAAD8Rrk3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"
  },
  //12
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/UDP(sport=31337, dport=6080)/IPv6(src="fc00:2307:1::2", dst="fc00:1::1")/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABemkXwABT9XpgAAAAACMGQPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "gue ip6ip6 inline decap. INLINE_DECAP_GUE is required",
    .expectedReturnValue = "XDP_TX",
    .expectedOutputPacket = "AADerb6vAgAAAAAAht1gAAAAAFMRQPwAIwcAAAAAAAAAAAAAEzf8AAAAAAAAAAAAAAAjBwADemkXwABTAABgAAAAACMGP/wAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
  //13
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IP(src="192.168.1.3", dst="10.200.1.1", ttl=1)/UDP(sport=31337, dport=80)/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAADMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABBTkXwAAznsJFAAArAAEAAAER7E3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0",
    .description = "gue ip4ip6 inline decap ttl 1. INLINE_DECAP_GUE is required",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAACABFAAArAAEAAAAR7E3AqAEDCsgBAXppAFAAF5fca2F0cmFuIHRlc3QgcGt0"
  },
  //14
  {
    //Ether(src="0x1", dst="0x2")/IPv6(src="100::64", dst="fc00:1404::1")/IPv6(src="fc00:2307:1::2", dst="fc00:1::1", hlim=1)/TCP(sport=31337, dport=80,flags="A")/"katran test pkt"
    .inputPacket = "AgAAAAAAAQAAAAAAht1gAAAAAFMRQAEAAAAAAAAAAAAAAAAAAGT8ABQEAAAAAAAAAAAAAAABBTkXwABTaupgAAAAACMGAfwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q=",
    .description = "gue ip6ip6 inline decap ttl 1. INLINE_DECAP_GUE is required",
    .expectedReturnValue = "XDP_DROP",
    .expectedOutputPacket = "AgAAAAAAAQAAAAAAht1gAAAAACMGAPwAIwcAAQAAAAAAAAAAAAL8AAABAAAAAAAAAAAAAAABemkAUAAAAAAAAAAAUBAgANpIAABrYXRyYW4gdGVzdCBwa3Q="
  },
};

}
}
