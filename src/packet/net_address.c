#include "packet/net_address.h"
#include <string.h>

const uint8_t           MAC_BLOCK_WIDTH         = 2;      /*  8-bit, WIDTH=1: 4-bit */
const uint8_t           IPV6_BLOCK_WIDTH        = 4;      /* 16-bit, WIDTH=1: 4-bit */
const uint8_t           HEXADECIMAL_LOWER[]     = "0123456789abcdef";
const mac_address_t     MAC_ADDRESS_NULL        = { .addr   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
const mac_address_t     MAC_ADDRESS_BROADCAST   = { .addr   = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
const ipv4_address_t    IPV4_ADDRESS_NULL       = { { .addr   = { 0, 0, 0, 0 } } };
const ipv6_address_t    IPV6_ADDRESS_NULL       = { { .addr32 = { 0, 0, 0, 0 } } };

bool
mac_address_convert_from_string(mac_address_t *mac, const uint8_t *str)
{
    uint16_t                i;
    
    /* 0  2 3  5 6  8 9  11   13   */
    /* xx : xx : xx : xx : xx : xx */
    if (str != NULL) {
        if (strnlen((const char *) str, STR_MAC_ADDRESS_MAX_LEN) != (STR_MAC_ADDRESS_MAX_LEN - 1)) {
            return false;
        }
        for (; *str != '\0' && i < MAC_ADDRESS_LEN; str += 3, i++) {
            hexstr2num(&(mac->addr[i]), str, MAC_BLOCK_WIDTH);
            if (str[2] != ':' && str[2] != '\0') {
                return false;
            }
        }
    }
    
    return true;
}

bool
mac_address_convert_to_string(const mac_address_t *mac, uint8_t *str)
{
    uint16_t                i;
    uint8_t                 chr[MAC_BLOCK_WIDTH];
    uint16_t                len = 0;
    
    /* iterate over 6 blocks */
    for (i = 0; i < MAC_ADDRESS_LEN; i++) {
        /* MAC address block is zero */
        if (mac->addr[i] == 0) {
            str[len++] = '0';
            str[len++] = '0';
            
        /* MAC block is _NOT_ zero */
        } else {
            num2hexstr(mac->addr[i], chr, MAC_BLOCK_WIDTH);
            str[len++] = chr[0];
            str[len++] = chr[1];
        }
        str[len++] = ':';
    }
    str[--len] = '\0';
    
    return true;
}

#define NETWORK_ADDRESS_CONVERTED 1

bool
ipv4_address_convert_from_string(ipv4_address_t *ipv4, const uint8_t *str)
{
    if (inet_pton(AF_INET, (const char *) str, &(ipv4->addr32)) != NETWORK_ADDRESS_CONVERTED) {
        return false;
    }
    return true;
}

bool
ipv4_address_convert_to_string(const ipv4_address_t *ipv4, uint8_t *str)
{
    if (inet_ntop(AF_INET, &(ipv4->addr32), (char *) str, STR_IPV4_ADDRESS_MAX_LEN) == NULL) {
        return false;
    }
    return true;
}

/**
 * Converts a 32-bit number (unsigned integer) to an ASCII character-arry
 * WITHOUT the prefix '0x' and the NUL terminator
 *
 * @param num           32-bit number to be converted
 * @param chr           an already allocated reference to a fixed length character-array
 * @param len           length of the character-array
 */
void
num2hexstr(uint32_t num, uint8_t *chr, size_t len)
{
    uint8_t    *reverse = &(chr[len]);
    
    while (len) {
        *--reverse = HEXADECIMAL_LOWER[num & 0x0f];
        num >>= 4;
        len--;
    }
}

/**
 * Converts an ASCII character-arry WITHOUT prefix '0x' but could include
 * NUL terminator to a 32-bit number (unsigned integer)
 *
 * 
 * example:
 * idx:       4   3   2   1   0
 * str: 0 x   1   b   e   e   f
 *
 * @param num           32-bit number to be converted
 * @param chr           an already allocated reference to a fixed length character-array
 * @param len           length of the character-array (= the last character of the string!)
 */
//void
//hexstr2u32(uint32_t *num, const uint8_t *str, size_t maxlen)
//{
//    uint8_t         len;
//    const uint8_t  *reverse;
//    uint8_t         chr         = 0;
//    uint8_t         shift       = 0;
//    uint8_t         nibble[2]   = { 0, 0 };
//    uint8_t         idx         = 0;
//
//    /* set len to maxlen first */
//    len = maxlen;
//
//    /* find the NUL-character */
//    for (idx = 0; idx < maxlen; idx++) {
//        if (str[idx] == '\0') {
//            len = idx;
//            break;
//        }
//    }
//
//    /* point to the last character in the array */
//    reverse = &(str[len]);
//
//    idx = 0;
//    while (idx < len) {
//        nibble[0] = 0;
//        nibble[1] = 0;
//
//        do {
//            chr = *--reverse;
//            if (chr >= '0' && chr <= '9') {
//                nibble[idx % 2] = chr - '0';
//            } else if (chr >= 'a' && chr <= 'f') {
//                nibble[idx % 2] = chr - 'a' + 10;
//            }
//            idx++;
//        } while (idx % 2 == 1 && idx < len);
//        *num += (nibble[1] << 4 | nibble[0]) << (8 * shift++);
//    }
//}
//
//void
//hexstr2u8(uint8_t *num, const uint8_t *str, size_t maxlen)
//{
//    uint8_t         len;
//    const uint8_t  *reverse;
//    uint8_t         chr         = 0;
//    uint8_t         shift       = 0;
//    uint8_t         nibble[2]   = { 0, 0 };
//    uint8_t         idx         = 0;
//
//    /* set len to maxlen first */
//    len = maxlen;
//
//    /* find the NUL-character */
//    for (idx = 0; idx < maxlen; idx++) {
//        if (str[idx] == '\0') {
//            len = idx;
//            break;
//        }
//    }
//
//    /* point to the last character in the array */
//    reverse = &(str[len]);
//
//    idx = 0;
//    while (idx < len) {
//        nibble[0] = 0;
//        nibble[1] = 0;
//
//        do {
//            chr = *--reverse;
//            if (chr >= '0' && chr <= '9') {
//                nibble[idx % 2] = chr - '0';
//            } else if (chr >= 'a' && chr <= 'f') {
//                nibble[idx % 2] = chr - 'a' + 10;
//            }
//            idx++;
//        } while (idx % 2 == 1 && idx < len);
//        *num += (nibble[1] << 4 | nibble[0]) << (8 * shift++);
//    }
//}

void
hexstr2num(void *num, const uint8_t *str, size_t maxlen)
{
    uint8_t         len;
    const uint8_t  *reverse;
    uint8_t         chr         = 0;
    uint8_t         shift       = 0;
    uint8_t         nibble[2]   = { 0, 0 };
    uint8_t         idx         = 0;

    /* set len to maxlen first */
    len = maxlen;

    /* find the NUL-character */
    for (idx = 0; idx < maxlen; idx++) {
        if (str[idx] == '\0') {
            len = idx;
            break;
        }
    }

    /* point to the last character in the array */
    reverse = &(str[len]);

    idx = 0;
    while (idx < len) {
        nibble[0] = 0;
        nibble[1] = 0;

        do {
            chr = *--reverse;
            if (chr >= '0' && chr <= '9') {
                nibble[idx % 2] = chr - '0';
            } else if (chr >= 'a' && chr <= 'f') {
                nibble[idx % 2] = chr - 'a' + 10;
            }
            idx++;
        } while (idx % 2 == 1 && idx < len);
        if      (maxlen <= 2) *( (uint8_t *) num) += (nibble[1] << 4 | nibble[0]) << (8 * shift++);
        else if (maxlen <= 4) *((uint16_t *) num) += (nibble[1] << 4 | nibble[0]) << (8 * shift++);
        else                  *((uint32_t *) num) += (nibble[1] << 4 | nibble[0]) << (8 * shift++);
    }
}
