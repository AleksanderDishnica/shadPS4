// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

// Runs fn(ctx) under an SEH guard on Windows: an access violation inside fn
// (e.g. heap corruption landing in the shader compiler) is caught and reported
// as a failure instead of terminating the process.
extern "C" bool SehGuardRun(void (*fn)(void*), void* ctx);
