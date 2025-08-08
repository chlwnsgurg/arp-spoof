#pragma once

#include "pch.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthHdr {
    Mac dmac_;
    Mac smac_;
    uint16_t type_;

    Mac dmac() { return dmac_; }
    Mac smac() { return smac_; }
    uint16_t type() { return ntohs(type_); }

    // type_
    enum: uint16_t {
        ETHERTYPE_IPV4 = 0x0800,
        ETHERTYPE_ARP = 0x0806,
        ETHERTYPE_IPV6 = 0x86DD
    };
};
#pragma pack(pop)


