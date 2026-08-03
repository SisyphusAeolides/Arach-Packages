#ifndef ARACH_PKGMETA_PROBE_H
#define ARACH_PKGMETA_PROBE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARACH_PKGMETA_MAX_BYTES (512u * 1024u)
#define ARACH_PKGMETA_MAX_LINE_BYTES 4096u
#define ARACH_PKGMETA_MAX_PACKAGES 4096u
#define ARACH_PKGMETA_MAX_PACKAGE_BYTES 128u
#define ARACH_PKGMETA_MAX_FIELDS 65535u

struct arach_pkgmeta_result {
    uint32_t package_count;
    uint32_t field_count;
    size_t byte_count;
};

enum arach_pkgmeta_status {
    ARACH_PKGMETA_OK = 0,
    ARACH_PKGMETA_NULL = 1,
    ARACH_PKGMETA_TOO_LARGE = 2,
    ARACH_PKGMETA_CONTROL_BYTE = 3,
    ARACH_PKGMETA_LINE_TOO_LONG = 4,
    ARACH_PKGMETA_INVALID_FIELD = 5,
    ARACH_PKGMETA_MISSING_PKGBASE = 6,
    ARACH_PKGMETA_MISSING_PACKAGE = 7,
    ARACH_PKGMETA_DUPLICATE_PACKAGE = 8,
    ARACH_PKGMETA_CAPACITY = 9
};

/*
 * Performs a bounded structural preflight of .SRCINFO bytes. This function
 * never grants package authority and never executes package code. A successful
 * result must still pass Corinth's signed, semantic importer.
 */
enum arach_pkgmeta_status arach_pkgmeta_probe(
    const uint8_t *bytes,
    size_t length,
    struct arach_pkgmeta_result *result
);

#ifdef __cplusplus
}
#endif

#endif
