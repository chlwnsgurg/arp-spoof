#include "pch.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr {

    uint8_t hl_:4,v_:4;   /* header length | version */
    uint8_t tos_;           /* type of service */
    uint16_t len_;          /* total length */
    uint16_t id_;           /* identification */
    uint16_t off_;
    uint8_t ttl_;           /* time to live */
    uint8_t proto_;             /* protocol */
    uint16_t sum_;         /* checksum */
    Ip sip_;         /* source ip address */
    Ip dip_;         /* destination ip address */

    uint8_t v() { return v_; }
    uint8_t hl() { return hl_; }
    uint8_t tos() { return tos_; }
    uint16_t len() { return ntohs(len_); }
    uint16_t id() { return ntohs(id_); }
    uint16_t off() { return ntohs(off_); }
    uint8_t ttl() { return ttl_; }
    uint8_t proto() { return proto_; }
    uint16_t sum() { return ntohs(sum_); }
    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }

    enum : uint8_t {
        IPPROTO_ICMP = 1,
        IPPROTO_IGMP = 2,
        IPPROTO_TCP = 6,
        IPPROTO_UDP = 17,
        IPPROTO_GRE = 47,
        IPPROTO_ESP = 50,
        IPPROTO_AH = 51,
    };
};
#pragma pack(pop)