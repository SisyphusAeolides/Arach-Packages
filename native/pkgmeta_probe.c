#include "pkgmeta_probe.h"

#include <stdbool.h>
#include <string.h>

struct byte_slice {
    const uint8_t *data;
    size_t length;
};

static bool is_space(uint8_t byte) {
    return byte == (uint8_t)' ' || byte == (uint8_t)'\t';
}

static bool is_key_byte(uint8_t byte) {
    return (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
           (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
           byte == (uint8_t)'_';
}

static bool is_package_byte(uint8_t byte) {
    return (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
           (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
           byte == (uint8_t)'+' || byte == (uint8_t)'-' ||
           byte == (uint8_t)'_' || byte == (uint8_t)'.' ||
           byte == (uint8_t)'@';
}

static bool slice_equals_literal(
    const struct byte_slice slice,
    const char *literal
) {
    const size_t literal_length = strlen(literal);
    return slice.length == literal_length &&
           memcmp(slice.data, literal, literal_length) == 0;
}

static bool slice_equals(
    const struct byte_slice left,
    const struct byte_slice right
) {
    return left.length == right.length &&
           memcmp(left.data, right.data, left.length) == 0;
}

static struct byte_slice trim(
    const uint8_t *data,
    size_t begin,
    size_t end
) {
    while (begin < end && is_space(data[begin])) {
        begin += 1u;
    }
    while (end > begin && is_space(data[end - 1u])) {
        end -= 1u;
    }
    return (struct byte_slice){
        .data = data + begin,
        .length = end - begin,
    };
}

static enum arach_pkgmeta_status validate_package_name(
    const struct byte_slice package
) {
    if (package.length == 0u ||
        package.length > ARACH_PKGMETA_MAX_PACKAGE_BYTES) {
        return ARACH_PKGMETA_INVALID_FIELD;
    }
    const uint8_t first = package.data[0];
    if (!((first >= (uint8_t)'a' && first <= (uint8_t)'z') ||
          (first >= (uint8_t)'0' && first <= (uint8_t)'9'))) {
        return ARACH_PKGMETA_INVALID_FIELD;
    }
    for (size_t index = 0u; index < package.length; index += 1u) {
        if (!is_package_byte(package.data[index])) {
            return ARACH_PKGMETA_INVALID_FIELD;
        }
    }
    return ARACH_PKGMETA_OK;
}

enum arach_pkgmeta_status arach_pkgmeta_probe(
    const uint8_t *bytes,
    const size_t length,
    struct arach_pkgmeta_result *result
) {
    if (result == NULL || (bytes == NULL && length != 0u)) {
        return ARACH_PKGMETA_NULL;
    }
    if (length > ARACH_PKGMETA_MAX_BYTES) {
        return ARACH_PKGMETA_TOO_LARGE;
    }

    for (size_t index = 0u; index < length; index += 1u) {
        const uint8_t byte = bytes[index];
        if ((byte < 0x20u && byte != (uint8_t)'\t' &&
             byte != (uint8_t)'\n' && byte != (uint8_t)'\r') ||
            byte == 0x7fu) {
            return ARACH_PKGMETA_CONTROL_BYTE;
        }
    }

    struct byte_slice packages[ARACH_PKGMETA_MAX_PACKAGES];
    size_t package_count = 0u;
    uint32_t field_count = 0u;
    uint32_t pkgbase_count = 0u;
    size_t cursor = 0u;

    while (cursor < length) {
        const size_t line_begin = cursor;
        while (cursor < length && bytes[cursor] != (uint8_t)'\n') {
            cursor += 1u;
        }
        size_t line_end = cursor;
        if (line_end > line_begin && bytes[line_end - 1u] == (uint8_t)'\r') {
            line_end -= 1u;
        }
        if (line_end - line_begin > ARACH_PKGMETA_MAX_LINE_BYTES) {
            return ARACH_PKGMETA_LINE_TOO_LONG;
        }
        if (cursor < length) {
            cursor += 1u;
        }

        struct byte_slice line = trim(bytes, line_begin, line_end);
        if (line.length == 0u || line.data[0] == (uint8_t)'#') {
            continue;
        }

        size_t equals = 0u;
        while (equals < line.length && line.data[equals] != (uint8_t)'=') {
            equals += 1u;
        }
        if (equals == line.length) {
            return ARACH_PKGMETA_INVALID_FIELD;
        }

        const size_t absolute_line = (size_t)(line.data - bytes);
        struct byte_slice key = trim(
            bytes,
            absolute_line,
            absolute_line + equals
        );
        struct byte_slice value = trim(
            bytes,
            absolute_line + equals + 1u,
            absolute_line + line.length
        );
        if (key.length == 0u || value.length == 0u) {
            return ARACH_PKGMETA_INVALID_FIELD;
        }
        for (size_t index = 0u; index < key.length; index += 1u) {
            if (!is_key_byte(key.data[index])) {
                return ARACH_PKGMETA_INVALID_FIELD;
            }
        }
        if (field_count == ARACH_PKGMETA_MAX_FIELDS) {
            return ARACH_PKGMETA_CAPACITY;
        }
        field_count += 1u;

        if (slice_equals_literal(key, "pkgbase")) {
            pkgbase_count += 1u;
            if (pkgbase_count != 1u ||
                validate_package_name(value) != ARACH_PKGMETA_OK) {
                return ARACH_PKGMETA_INVALID_FIELD;
            }
        } else if (slice_equals_literal(key, "pkgname")) {
            if (validate_package_name(value) != ARACH_PKGMETA_OK) {
                return ARACH_PKGMETA_INVALID_FIELD;
            }
            if (package_count == ARACH_PKGMETA_MAX_PACKAGES) {
                return ARACH_PKGMETA_CAPACITY;
            }
            for (size_t index = 0u; index < package_count; index += 1u) {
                if (slice_equals(packages[index], value)) {
                    return ARACH_PKGMETA_DUPLICATE_PACKAGE;
                }
            }
            packages[package_count] = value;
            package_count += 1u;
        }
    }

    if (pkgbase_count != 1u) {
        return ARACH_PKGMETA_MISSING_PKGBASE;
    }
    if (package_count == 0u) {
        return ARACH_PKGMETA_MISSING_PACKAGE;
    }

    *result = (struct arach_pkgmeta_result){
        .package_count = (uint32_t)package_count,
        .field_count = field_count,
        .byte_count = length,
    };
    return ARACH_PKGMETA_OK;
}
