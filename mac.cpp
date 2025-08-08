#include "mac.h"

Mac& Mac::nullMac() {
    static uint8_t _value[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static Mac res(_value);
    return res;
}

Mac& Mac::broadcastMac() {
    static uint8_t _value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static Mac res(_value);
    return res;
}