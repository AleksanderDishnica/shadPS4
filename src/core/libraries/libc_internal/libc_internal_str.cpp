// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/assert.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/libs.h"
#include "libc_internal_str.h"

namespace Libraries::LibcInternal {

s32 PS4_SYSV_ABI internal_strcpy_s(char* dest, size_t dest_size, const char* src) {
    // PS4 libc semantics: return an error code on failure instead of
    // terminating the process (MSVC's strcpy_s invokes the invalid parameter
    // handler which fastfails).
    if (dest == nullptr || dest_size == 0) {
        return 22; // EINVAL
    }
    if (src == nullptr) {
        dest[0] = '\0';
        return 22; // EINVAL
    }
    const size_t len = std::strlen(src);
    if (len + 1 > dest_size) {
        std::memcpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 34; // ERANGE
    }
    std::memcpy(dest, src, len + 1);
    return 0;
}

s32 PS4_SYSV_ABI internal_strcat_s(char* dest, size_t dest_size, const char* src) {
    if (dest == nullptr || dest_size == 0) {
        return 22; // EINVAL
    }
    if (src == nullptr) {
        return 22; // EINVAL
    }
    const size_t dlen = strnlen(dest, dest_size);
    if (dlen == dest_size) {
        return 22; // EINVAL — dest not null-terminated
    }
    const size_t slen = std::strlen(src);
    if (dlen + slen + 1 > dest_size) {
        return 34; // ERANGE
    }
    std::memcpy(dest + dlen, src, slen + 1);
    return 0;
}

s32 PS4_SYSV_ABI internal_strcmp(const char* str1, const char* str2) {
    return std::strcmp(str1, str2);
}

s32 PS4_SYSV_ABI internal_strncmp(const char* str1, const char* str2, size_t num) {
    return std::strncmp(str1, str2, num);
}

size_t PS4_SYSV_ABI internal_strlen(const char* str) {
    return std::strlen(str);
}

char* PS4_SYSV_ABI internal_strncpy(char* dest, const char* src, std::size_t count) {
    return std::strncpy(dest, src, count);
}

s32 PS4_SYSV_ABI internal_strncpy_s(char* dest, size_t destsz, const char* src, size_t count) {
    // PS4 libc semantics: return an error code on failure instead of
    // terminating the process (MSVC's strncpy_s invokes the invalid parameter
    // handler which fastfails).
    if (dest == nullptr || destsz == 0) {
        return 22; // EINVAL
    }
    if (src == nullptr) {
        dest[0] = '\0';
        return 22; // EINVAL
    }
    const size_t len = strnlen(src, count);
    if (len >= destsz) {
        // Truncate and report range error, like the PS4 implementation.
        std::memcpy(dest, src, destsz - 1);
        dest[destsz - 1] = '\0';
        return 34; // ERANGE
    }
    std::memcpy(dest, src, len);
    // strncpy pads the remainder with zeros up to count — replicate.
    std::memset(dest + len, 0, count - len);
    return 0;
}

char* PS4_SYSV_ABI internal_strcat(char* dest, const char* src) {
    return std::strcat(dest, src);
}

const char* PS4_SYSV_ABI internal_strchr(const char* str, int c) {
    return std::strchr(str, c);
}

void RegisterlibSceLibcInternalStr(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("5Xa2ACNECdo", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strcpy_s);
    LIB_FUNCTION("K+gcnFFJKVc", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strcat_s);
    LIB_FUNCTION("Ovb2dSJOAuE", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strcmp);
    LIB_FUNCTION("aesyjrHVWy4", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strncmp);
    LIB_FUNCTION("j4ViWNHEgww", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strlen);
    LIB_FUNCTION("6sJWiWSRuqk", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strncpy);
    LIB_FUNCTION("YNzNkJzYqEg", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strncpy_s);
    LIB_FUNCTION("Ls4tzzhimqQ", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strcat);
    LIB_FUNCTION("ob5xAW4ln-0", "libSceLibcInternal", 1, "libSceLibcInternal", internal_strchr);
}

} // namespace Libraries::LibcInternal
