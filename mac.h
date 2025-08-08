#pragma once

#include "pch.h"


struct Mac {
    static constexpr int Size = 6;

    // constructor
    Mac() {}
    Mac(const uint8_t* r) { memcpy(this->mac_, r, Size); }
    Mac(const std::string& r) {
        std::string s;
        for(char ch: r) {
            if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
                s += ch;
        }
        int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
        if (res != Size) {
            fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
            return;
        }
    }

    // casting operator
    explicit operator std::string() const {
        char buf[20]; // enough size
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
        return std::string(buf);
    }

    // comparison operator
    bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, Size) == 0; }

    bool isNull() const {
        return *this == nullMac();
    }

    bool isBroadcast() const { // FF:FF:FF:FF:FF:FF
        return *this == broadcastMac();
    }

    bool isMulticast() const { // 01:00:5E:0*
        return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
    }

    static Mac& nullMac();
    static Mac& broadcastMac();

protected:
    uint8_t mac_[Size];
};

namespace std {
    template<>
    struct hash<Mac> {
        size_t operator() (const Mac& r) const {
            return std::_Hash_impl::hash(&r, Mac::Size);
        }
    };
}
