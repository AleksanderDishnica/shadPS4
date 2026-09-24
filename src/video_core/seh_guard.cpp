// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "video_core/seh_guard.h"

#ifdef _WIN32
#include <windows.h>

extern "C" bool SehGuardRun(void (*fn)(void*), void* ctx) {
    __try {
        fn(ctx);
        return true;
    } __except (GetExceptionCode() == 0xC0000005 ? EXCEPTION_EXECUTE_HANDLER
                                                 : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

#else

extern "C" bool SehGuardRun(void (*fn)(void*), void* ctx) {
    fn(ctx);
    return true;
}

#endif
