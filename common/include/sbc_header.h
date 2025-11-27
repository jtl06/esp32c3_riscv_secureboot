#ifndef SBC_HEADER_H
#define SBC_HEADER_H

#include <stdint.h>

#define SBC_HEADER_MAGIC 0x53424331 // "SBC1"

typedef struct {
    uint32_t magic;         // Magic number to identify the header
    uint32_t img_size;      // Size of the image (excluding header)
    uint32_t img_version;   // Version of the image
    uint8_t  img_hash[32];  // SHA-256 hash of the image
    uint8_t  sig[64];       // ECDSA P-256 signature (r, s)
} sbc_header_t;

#endif // SBC_HEADER_H
