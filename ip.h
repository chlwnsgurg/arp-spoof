#pragma once

#include "pch.h"

struct Ip {
    static const int Size = 4;

    // constructor
    Ip() {}
    Ip(const uint32_t r) : ip_(r) {}
    Ip(const std::string& r) {
        uint8_t a, b, c, d;
        int res = sscanf(r.c_str(), "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
        if (res != Size) {
            fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
            return;
        }
        ip_ = (a << 24) | (b << 16) | (c << 8) | d;
    }

    // casting operator
    operator uint32_t() const { return ip_; }
    explicit operator std::string() const {
        char buf[32]; // enough size
        sprintf(buf, "%u.%u.%u.%u",(ip_>>24)&0xFF,(ip_>>16)&0xFF,(ip_>>8)&0xFF,(ip_&0xFF));
        return std::string(buf);
    }

    // comparison operator
    bool operator == (const Ip& r) const { return ip_ == r.ip_; }

    bool isLocalHost() const { // 127.*.*.*
        uint8_t prefix = (ip_ & 0xFF000000) >> 24;
        return prefix == 0x7F;
    }
    bool isBroadcast() const { // 255.255.255.255
        return ip_ == 0xFFFFFFFF;
    }
    bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
        uint8_t prefix = (ip_ & 0xFF000000) >> 24;
        return prefix >= 0xE0 && prefix < 0xF0;
    }

protected:
    uint32_t ip_;
};
