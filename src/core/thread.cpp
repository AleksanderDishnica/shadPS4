// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/alignment.h"
#include "common/arch.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "thread.h"
#ifdef _WIN64
#include <windows.h>
#include "common/ntapi.h"
#else
#include <csignal>
#include <pthread.h>
#include <unistd.h>
#ifdef ARCH_X86_64
#include <xmmintrin.h>
#endif
#endif

namespace Core {

static constexpr u32 ORBIS_MXCSR = 0x9fc0;
static constexpr u32 ORBIS_FPUCW = 0x037f;

NativeThread::NativeThread() : native_handle{0} {}

NativeThread::~NativeThread() {}

int NativeThread::Create(ThreadFunc func, void* arg) {
#ifndef _WIN64
    pthread_t* pthr = reinterpret_cast<pthread_t*>(&native_handle);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    // PS4 thread stacks are fully committed at creation time; some games
    // (e.g. Dreams' internal JIT) access stack memory far above the current
    // stack pointer, which would fault on lazily committed host stacks.
    pthread_attr_setstacksize(&attr, 8_MB);
    return pthread_create(pthr, &attr, func, arg);
#else
    // CreateThread commits only dwStackSize bytes eagerly. Use a large
    // eagerly-committed stack so guest code reading above the stack pointer
    // (PS4 stacks are fully committed from creation) does not fault.
    native_handle = CreateThread(nullptr, 8_MB, func, arg, 0, nullptr);
    if (native_handle == nullptr) {
        return GetLastError();
    }
    return 0;
#endif
}

void NativeThread::Exit() {
    if (!native_handle) {
        return;
    }

    tid = 0;

#ifdef _WIN64
    native_handle = nullptr;
    ExitThread(0);
#else
    // Disable and free the signal stack.
    constexpr stack_t sig_stack = {
        .ss_flags = SS_DISABLE,
    };
    sigaltstack(&sig_stack, nullptr);

    if (sig_stack_ptr) {
        free(sig_stack_ptr);
        sig_stack_ptr = nullptr;
    }
    pthread_exit(nullptr);
#endif
}

void NativeThread::Initialize() {
#ifdef ARCH_X86_64
    // Set MXCSR and FPUCW registers to the values used by Orbis.
    _mm_setcsr(ORBIS_MXCSR);
    asm volatile("fldcw %0" : : "m"(ORBIS_FPUCW));
#endif
#if _WIN64
    tid = GetCurrentThreadId();
    // PS4 thread stacks are fully committed from creation. Some guest code
    // (e.g. Dreams' internal JIT) reads stack memory far above the current
    // stack pointer, which hard-faults on Windows' lazily grown stacks.
    // Commit the entire stack reservation up front.
    {
        NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
        MEMORY_BASIC_INFORMATION alloc{};
        if (VirtualQuery(tib->StackLimit, &alloc, sizeof(alloc)) != 0 &&
            alloc.AllocationBase != nullptr) {
            const u64 total = reinterpret_cast<u64>(tib->StackBase) -
                              reinterpret_cast<u64>(alloc.AllocationBase);
            if (total > 0 && total < 1_GB) {
                VirtualAlloc(alloc.AllocationBase, total, MEM_COMMIT, PAGE_READWRITE);
            }
        }
    }
#else
    tid = (u64)pthread_self();

    // Set up an alternate signal handler stack to avoid overflowing small thread stacks.
    const size_t page_size = getpagesize();
    const size_t sig_stack_size = Common::AlignUp(std::max<size_t>(64_KB, MINSIGSTKSZ), page_size);
    ASSERT_MSG(posix_memalign(&sig_stack_ptr, page_size, sig_stack_size) == 0,
               "Failed to allocate signal stack: {}", errno);

    stack_t sig_stack;
    sig_stack.ss_sp = sig_stack_ptr;
    sig_stack.ss_size = sig_stack_size;
    sig_stack.ss_flags = 0;
    ASSERT_MSG(sigaltstack(&sig_stack, nullptr) == 0, "Failed to set signal stack: {}", errno);
#endif
}

} // namespace Core
