#include "pkgmeta_probe.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int expect_status(
    const char *label,
    const uint8_t *bytes,
    const size_t length,
    const enum arach_pkgmeta_status expected
) {
    struct arach_pkgmeta_result result = {0};
    const enum arach_pkgmeta_status actual =
        arach_pkgmeta_probe(bytes, length, &result);
    if (actual != expected) {
        (void)fprintf(
            stderr,
            "%s: expected status %d, received %d\n",
            label,
            (int)expected,
            (int)actual
        );
        return 1;
    }
    return 0;
}

int main(void) {
    static const uint8_t valid[] =
        "pkgbase = openblas\n"
        "\tpkgver = 0.3.34\n"
        "\tarch = x86_64\n"
        "\n"
        "pkgname = openblas\n"
        "\tdepends = glibc\n"
        "\n"
        "pkgname = openblas64\n";
    struct arach_pkgmeta_result result = {0};
    enum arach_pkgmeta_status status =
        arach_pkgmeta_probe(valid, sizeof(valid) - 1u, &result);
    if (status != ARACH_PKGMETA_OK ||
        result.package_count != 2u ||
        result.field_count != 6u ||
        result.byte_count != sizeof(valid) - 1u) {
        (void)fprintf(stderr, "valid split metadata was not measured exactly\n");
        return 1;
    }

    static const uint8_t duplicate[] =
        "pkgbase = demo\n"
        "pkgname = demo\n"
        "pkgname = demo\n";
    if (expect_status(
            "duplicate package",
            duplicate,
            sizeof(duplicate) - 1u,
            ARACH_PKGMETA_DUPLICATE_PACKAGE
        ) != 0) {
        return 2;
    }

    static const uint8_t missing_base[] = "pkgname = demo\n";
    if (expect_status(
            "missing pkgbase",
            missing_base,
            sizeof(missing_base) - 1u,
            ARACH_PKGMETA_MISSING_PKGBASE
        ) != 0) {
        return 3;
    }

    static const uint8_t missing_package[] = "pkgbase = demo\n";
    if (expect_status(
            "missing package",
            missing_package,
            sizeof(missing_package) - 1u,
            ARACH_PKGMETA_MISSING_PACKAGE
        ) != 0) {
        return 4;
    }

    static const uint8_t invalid_package[] =
        "pkgbase = demo\n"
        "pkgname = ../escape\n";
    if (expect_status(
            "invalid package",
            invalid_package,
            sizeof(invalid_package) - 1u,
            ARACH_PKGMETA_INVALID_FIELD
        ) != 0) {
        return 5;
    }

    static const uint8_t control_byte[] = {
        'p', 'k', 'g', 'b', 'a', 's', 'e', ' ', '=', ' ', 'd', 'e', 'm', 'o', '\n',
        'p', 'k', 'g', 'n', 'a', 'm', 'e', ' ', '=', ' ', 'd', 'e', 0u, 'm', 'o', '\n'
    };
    if (expect_status(
            "control byte",
            control_byte,
            sizeof(control_byte),
            ARACH_PKGMETA_CONTROL_BYTE
        ) != 0) {
        return 6;
    }

    static uint8_t long_line[ARACH_PKGMETA_MAX_LINE_BYTES + 2u];
    (void)memset(long_line, 'a', sizeof(long_line));
    long_line[sizeof(long_line) - 1u] = '\n';
    if (expect_status(
            "long line",
            long_line,
            sizeof(long_line),
            ARACH_PKGMETA_LINE_TOO_LONG
        ) != 0) {
        return 7;
    }

    if (arach_pkgmeta_probe(valid, sizeof(valid) - 1u, NULL) != ARACH_PKGMETA_NULL) {
        (void)fprintf(stderr, "null result was accepted\n");
        return 8;
    }

    return 0;
}
