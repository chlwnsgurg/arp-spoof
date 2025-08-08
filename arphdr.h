#pragma once

#include "pch.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct ArpHdr final {
    uint16_t hrd_;
    uint16_t pro_;
    uint8_t hln_;
    uint8_t pln_;
    uint16_t op_;
    Mac smac_;
    Ip sip_;
    Mac tmac_;
    Ip tip_;

    uint16_t hrd() { return ntohs(hrd_); }
    uint16_t pro() { return ntohs(pro_); }
    uint8_t hln() { return hln_;}
    uint8_t pln() { return pln_;}
    uint16_t op() { return ntohs(op_); }
    Mac smac() { return smac_; }
    Ip sip() { return ntohl(sip_); }
    Mac tmac() { return tmac_; }
    Ip tip() { return ntohl(tip_); }


    // HardwareType(hrd_)
    enum: uint16_t {
        HTYPE_NETROM = 0, // from KA9Q: NET/ROM pseudo
        HTYPE_ETHER = 1, // Ethernet 10Mbps
        HTYPE_EETHER = 2, // Experimental Ethernet
        HTYPE_AX25 = 3, // AX.25 Level 2
        HTYPE_PRONET = 4, // PROnet token ring
        HTYPE_CHAOS = 5, // Chaosnet
        HTYPE_IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
        HTYPE_ARCNET = 7, // ARCnet
        HTYPE_APPLETLK = 8, // APPLEtalk
        HTYPE_LANSTAR = 9, // Lanstar
        HTYPE_DLCI = 15, // Frame Relay DLCI
        HTYPE_ATM = 19, // ATM
        HTYPE_METRICOM = 23, // Metricom STRIP (new IANA id)
        HTYPE_IPSEC = 31 // IPsec tunnel
        };

    // Operation(op_)
    enum: uint16_t {
        OP_REQUEST = 1, // req to resolve address
        OP_REPLY = 2, // resp to previous request
        OP_REVREQUEST = 3, // req protocol address given hardware
        OP_REVREPLY = 4, // resp giving protocol address
        OP_INVREQUEST = 8, // req to identify peer
        OP_INVREPLY = 9 // resp identifying peer
        };
};
#pragma pack(pop)