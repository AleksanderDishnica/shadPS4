// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/arch.h"
#include "common/assert.h"
#include "common/decoder.h"
#include "common/signal_context.h"
#include "core/cpu_patches.h" // Windows static guest red-zone protection
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/kernel/threads/exception.h"
#include "core/signals.h"
#include "emulator.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
static constexpr DWORD MS_VC_EXCEPTION = 0x406D1388;

// Best-effort raw crash recorder. Uses only Win32 calls with a stack buffer so it can
// run inside the vectored exception handler even on tiny (64 KiB) guest fiber stacks,
// where spdlog-based logging would overflow and silently kill the process.
static bool IsFatalExceptionCode(DWORD code) noexcept {
    switch (code) {
    case 0xC0000005: // access violation
    case 0xC000001D: // illegal instruction
    case 0xC00000FD: // stack overflow
    case 0xC0000409: // fast fail
    case 0xC0000374: // heap corruption
    case 0x80000003: // breakpoint
        return true;
    default:
        return false;
    }
}

// Diagnostics: file crash reporting is disabled unless the
// SHADPS4_CRASH_REPORT environment variable is set. Its value is used as the
// output path; "1" writes crash_report.txt next to the executable.
static HANDLE OpenCrashReportFile() noexcept {
    char env[512]{};
    size_t len = 0;
    if (getenv_s(&len, env, sizeof(env) - 1, "SHADPS4_CRASH_REPORT") != 0 || len == 0) {
        return INVALID_HANDLE_VALUE;
    }
    std::wstring path;
    if (strcmp(env, "1") == 0) {
        path = L"crash_report.txt";
    } else {
        const int wlen = MultiByteToWideChar(CP_UTF8, 0, env, -1, nullptr, 0);
        path.resize(wlen);
        MultiByteToWideChar(CP_UTF8, 0, env, -1, path.data(), wlen);
    }
    return CreateFileW(path.c_str(), FILE_APPEND_DATA, 0, nullptr, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

static void AppendOneLine(const char* line, int n) noexcept {
    HANDLE f = OpenCrashReportFile();
    if (f != INVALID_HANDLE_VALUE) {
        SetFilePointer(f, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(f, line, n, &written, nullptr);
        CloseHandle(f);
    }
}

static void WriteCrashReport(EXCEPTION_POINTERS* pExp) noexcept {
    if (pExp == nullptr || pExp->ExceptionRecord == nullptr) {
        return;
    }
    static volatile LONG s_busy = 0;
    // Always leave a one-line record, even if another thread is mid-report.
    {
    static volatile LONG s_fault_log_count = 0;
    if (InterlockedIncrement(&s_fault_log_count) < 10000) {
        const auto* rec0 = pExp->ExceptionRecord;
        char line0[288];
        int n0 = 0;
        if (rec0->ExceptionCode == 0xE06D7363 && rec0->NumberParameters >= 3) {
            // MSVC C++ exception: capture the thrown object and throw-info
            // pointers for offline symbolication of the throwing function.
            n0 = _snprintf(line0, sizeof(line0),
                           "CPPTHROW tid=%#x magic=%#llx obj=%p throwinfo=%p\n",
                           GetCurrentThreadId(),
                           (unsigned long long)rec0->ExceptionInformation[0],
                           (void*)rec0->ExceptionInformation[1],
                           (void*)rec0->ExceptionInformation[2]);
        } else {
            n0 = _snprintf(line0, sizeof(line0),
                           "FAULT code=%#llx tid=%#x addr=%p access=%#llx target=%#llx\n",
                           (unsigned long long)rec0->ExceptionCode, GetCurrentThreadId(),
                           rec0->ExceptionAddress,
                           (unsigned long long)(rec0->NumberParameters > 0
                                                    ? rec0->ExceptionInformation[0]
                                                    : 0),
                           (unsigned long long)(rec0->NumberParameters > 1
                                                    ? rec0->ExceptionInformation[1]
                                                    : 0));
        }
        AppendOneLine(line0, n0);
    }
    }
    if (InterlockedCompareExchange(&s_busy, 1, 0) != 0) {
        return; // nested crash while recording; bail out
    }

    char buf[4096];
    DWORD len = 0;
    const auto append = [&](const char* s) noexcept {
        while (*s != '\0' && len < sizeof(buf) - 96) {
            buf[len++] = *s++;
        }
    };
    const auto append_hex = [&](unsigned long long v) noexcept {
        char tmp[17];
        tmp[16] = '\0';
        for (int i = 15; i >= 0; --i) {
            tmp[i] = "0123456789abcdef"[v & 0xf];
            v >>= 4;
        }
        append("0x");
        append(tmp);
    };

    const auto* rec = pExp->ExceptionRecord;
    append("EXCEPTION code=");
    append_hex(rec->ExceptionCode);
    append(" tid=");
    append_hex(GetCurrentThreadId());
    append(" addr=");
    append_hex(reinterpret_cast<unsigned long long>(rec->ExceptionAddress));
    if (rec->ExceptionCode == 0xC0000005 && rec->NumberParameters >= 2) {
        append(" access=");
        append_hex(rec->ExceptionInformation[0]);
        append(" target=");
        append_hex(rec->ExceptionInformation[1]);
    }
    append("\nBACKTRACE\n");
    void* frames[62];
    const USHORT n = CaptureStackBackTrace(0, 62, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        append_hex(reinterpret_cast<unsigned long long>(frames[i]));
        append("\n");
    }
    // Manual stack scan: fiber stacks defeat RtlCaptureStackBackTrace.
    // Look for return addresses into the guest eboot region and host modules.
    if (pExp->ContextRecord != nullptr) {
        append("STACKSCAN rsp=");
        append_hex(pExp->ContextRecord->Rsp);
        append("\n");
        // Host module ranges (shadPS4.exe + DLLs).
        HMODULE exe = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nullptr, &exe);
        const unsigned long long exe_base =
            reinterpret_cast<unsigned long long>(exe);
        unsigned long long exe_size = 0;
        if (exe != nullptr) {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), exe, &mi, sizeof(mi))) {
                exe_size = mi.SizeOfImage;
            }
        }
        const unsigned long long* sp =
            reinterpret_cast<unsigned long long*>(pExp->ContextRecord->Rsp);
        int found = 0;
        int host_found = 0;
        for (int i = 0; i < 8192 && (found < 24 || host_found < 32); ++i, ++sp) {
            __try {
                const unsigned long long v = sp[i];
                // Guest eboot code region (loaded at 0x5510000, size 0xb868000).
                if (v >= 0x5510000ULL && v < 0x10D78000ULL) {
                    append("  ret ");
                    append_hex(v);
                    append(" (off ");
                    append_hex(v - 0x5510000ULL);
                    append(")\n");
                    ++found;
                } else if (exe_size != 0 && v >= exe_base && v < exe_base + exe_size) {
                    append("  host ");
                    append_hex(v);
                    append(" (exe+0x");
                    append_hex(v - exe_base);
                    append(")\n");
                    ++host_found;
                }
            } __except (1) {
                break; // left the stack
            }
        }
        if (found == 0 && host_found == 0) {
            append("  (no frames found)\n");
        }
    }
    HMODULE mod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(rec->ExceptionAddress), &mod) &&
        mod != nullptr) {
        append("MODULE base=");
        append_hex(reinterpret_cast<unsigned long long>(mod));
        // Record module file name for identification.
        wchar_t wpath[512];
        const DWORD wl = GetModuleFileNameW(mod, wpath, 512);
        if (wl > 0 && wl < 512) {
            append(" name=");
            for (DWORD i = 0; i < wl; ++i) {
                const char c = (char)wpath[i];
                if (c >= 32 && c < 127 && len < sizeof(buf) - 96) {
                    buf[len++] = c;
                }
            }
        }
        append("\n");
    }
    // Report host protection status of the faulting code address and target.
    {
        MEMORY_BASIC_INFORMATION mbi{};
        const auto query = [&](const char* tag, unsigned long long a) noexcept {
            if (a == 0) {
                return;
            }
            if (VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof(mbi)) != 0) {
                append(tag);
                append(" qbase=");
                append_hex(reinterpret_cast<unsigned long long>(mbi.BaseAddress));
                append(" qsize=");
                append_hex(mbi.RegionSize);
                append(" protect=");
                append_hex(mbi.Protect);
                append(" state=");
                append_hex(mbi.State);
                append(" type=");
                append_hex(mbi.Type);
                append("\n");
            } else {
                append(tag);
                append(" VirtualQuery FAILED\n");
            }
        };
        query("RIPMEM ", reinterpret_cast<unsigned long long>(rec->ExceptionAddress));
        if (rec->NumberParameters > 1) {
            query("TGTMEM ", rec->ExceptionInformation[1]);
        }
    }
    append("END\n");

    HANDLE f = OpenCrashReportFile();
    if (f != INVALID_HANDLE_VALUE) {
        SetFilePointer(f, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(f, buf, len, &written, nullptr);
        CloseHandle(f);
    }
    InterlockedExchange(&s_busy, 0);
}
#else
#include <csignal>
#include <pthread.h>
#ifdef ARCH_X86_64
#include <Zydis/Formatter.h>
#endif
#endif

namespace Core {

#if defined(_WIN32)

// Throwing stub for crash-to-throw redirection: entered via RIP redirection
// from the VEH, throws so surrounding C++ handlers can recover.
__declspec(noreturn) void HostCrashThrowStub() {
    throw std::runtime_error("host code access violation (converted)");
}

static LONG WINAPI SignalHandler(EXCEPTION_POINTERS* pExp) noexcept {
    if (pExp != nullptr && pExp->ExceptionRecord != nullptr &&
        IsFatalExceptionCode(pExp->ExceptionRecord->ExceptionCode)) {
        WriteCrashReport(pExp);
    }

    // Windows grows thread stacks lazily via guard pages, and adjacent thread
    // stacks are left reserved (unreadable). On PS4 all thread stacks are
    // fully mapped, and adjacent stacks are readable — some guest code (e.g.
    // Dreams' internal JIT) relies on this when probing above its own stack.
    // If this fault targets a reserved page inside a small private allocation
    // (a thread stack reservation), commit the whole allocation and resume.
    if (pExp != nullptr && pExp->ExceptionRecord != nullptr &&
        pExp->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        pExp->ExceptionRecord->NumberParameters >= 2) {
        const auto target =
            reinterpret_cast<void*>(pExp->ExceptionRecord->ExceptionInformation[1]);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(target, &mbi, sizeof(mbi)) != 0 && mbi.State == MEM_RESERVE &&
            (mbi.Type & MEM_PRIVATE) != 0 && mbi.AllocationBase != nullptr) {
            // Bound the entire allocation; only service stack-sized ones.
            MEMORY_BASIC_INFORMATION alloc{};
            bool stack_sized = true;
            u64 total = 0;
            u8* probe = static_cast<u8*>(mbi.AllocationBase);
            u8* alloc_base = probe;
            for (int i = 0; i < 64 && probe < static_cast<u8*>(target) + 0x10000; ++i) {
                if (VirtualQuery(probe, &alloc, sizeof(alloc)) == 0 ||
                    alloc.AllocationBase != mbi.AllocationBase) {
                    break;
                }
                total = (static_cast<u8*>(alloc.BaseAddress) + alloc.RegionSize) - alloc_base;
                if (total > 16_MB) {
                    stack_sized = false;
                    break;
                }
                probe = static_cast<u8*>(alloc.BaseAddress) + alloc.RegionSize;
            }
            if (stack_sized && total > 0 && total <= 16_MB &&
                VirtualAlloc(alloc_base, total, MEM_COMMIT, PAGE_READWRITE) != nullptr) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    using namespace Libraries::Kernel;
    const auto* signals = Signals::Instance();

    const bool use_static_windows_guest_red_zone_protection =
        WindowsGuestRedZoneProtection::IsStaticPatchingEnabled();
    DWORD code = 0;
    PVOID address = nullptr;

    if (pExp != nullptr && pExp->ExceptionRecord != nullptr) {
        code = pExp->ExceptionRecord->ExceptionCode;
        address = pExp->ExceptionRecord->ExceptionAddress;
    }

    Ucontext guest_context{pExp->ContextRecord};
    Siginfo guest_info{
        ._si_signo = 0,
        ._si_errno = 0,
        ._si_code = POSIX_SI_NOINFO,
        ._si_addr = (void*)guest_context.uc_mcontext.mc_rip,
    };

    bool handled = false;
    bool static_protection_exception = false; // Windows static guest red-zone protection
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
        guest_info._si_signo = POSIX_SIGSEGV;
        guest_info._si_code = POSIX_SEGV_MAPERR;
        static_protection_exception = true; // Windows static guest red-zone protection
        handled = signals->DispatchAccessViolation(
            pExp, reinterpret_cast<void*>(pExp->ExceptionRecord->ExceptionInformation[1]));
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        guest_info._si_signo = POSIX_SIGILL;
        guest_info._si_code = POSIX_ILL_ILLOPC;
        static_protection_exception = true; // Windows static guest red-zone protection
        handled = signals->DispatchIllegalInstruction(pExp);
        break;
    case EXCEPTION_PRIV_INSTRUCTION: // Windows static guest red-zone protection
        if (use_static_windows_guest_red_zone_protection) {
            static_protection_exception = true;
            handled = signals->DispatchIllegalInstruction(pExp);
        }
        break;
    case EXCEPTION_IN_PAGE_ERROR:
        guest_info._si_signo = POSIX_SIGBUS;
        guest_info._si_code = POSIX_BUS_ADRALN;
        break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_INTDIV;
        break;
    case EXCEPTION_INT_OVERFLOW:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_INTOVF;
        break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTDIV;
        break;
    case EXCEPTION_FLT_INVALID_OPERATION:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTINV;
        break;
    case EXCEPTION_FLT_OVERFLOW:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTOVF;
        break;
    case EXCEPTION_FLT_UNDERFLOW:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTUND;
        break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTSUB; // i am not sure about this one
        break;
    case EXCEPTION_FLT_INEXACT_RESULT:
        guest_info._si_signo = POSIX_SIGFPE;
        guest_info._si_code = POSIX_FPE_FLTRES;
        break;
    case EXCEPTION_FLT_STACK_CHECK:
        guest_info._si_signo = POSIX_SIGILL;
        guest_info._si_code = POSIX_ILL_BADSTK; // i am not sure about this one either
        break;
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP:
        guest_info._si_signo = POSIX_SIGTRAP;
        guest_info._si_code = POSIX_TRAP_BRKPT;
        break;
    case DBG_PRINTEXCEPTION_C:
    case DBG_PRINTEXCEPTION_WIDE_C:
        // Used by OutputDebugString functions.
        return EXCEPTION_CONTINUE_EXECUTION;
    case MS_VC_EXCEPTION:
        LOG_DEBUG(Debug, "Pass MS_VC_EXCEPTION at {} to handler", address);
        return EXCEPTION_EXECUTE_HANDLER;
    default:
        break;
    }

    if (handled) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (guest_info._si_signo != 0) {
        const bool dispatched =
            g_curthread &&
            g_curthread->DispatchSignal(guest_info._si_signo, &guest_info, &guest_context);
        // Trace guest signal dispatch outcomes for high-address faults
        // (Dreams JIT arenas) to see which faults the guest handler accepts.
        const auto* rec_tr = pExp->ExceptionRecord;
        const u64 fault_target =
            (rec_tr != nullptr && rec_tr->NumberParameters > 1) ? rec_tr->ExceptionInformation[1]
                                                                : 0;
        if (fault_target >= 0x1000000000ULL || (uintptr_t)address >= 0x1000000000ULL) {
            LOG_WARNING(Debug,
                        "Guest signal rip={:#x} target={:#x} dispatched={} (curthread={})",
                        (uintptr_t)address, fault_target, dispatched, g_curthread != nullptr);
        }
        if (dispatched) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    const bool report_unhandled =
        use_static_windows_guest_red_zone_protection ? static_protection_exception : true;
    if (report_unhandled) {
        // Last resort compat: PS4 games fully own their direct-memory
        // allocations and routinely access the same physical memory through
        // aliases with different protections. If every handler declined and
        // the fault targets a guest mapping (MEM_MAPPED of our backing), relax
        // the protection instead of dying: NoAccess -> RW, ReadOnly -> RW for
        // write faults.
        if (code == EXCEPTION_ACCESS_VIOLATION && pExp != nullptr &&
            pExp->ExceptionRecord != nullptr &&
            pExp->ExceptionRecord->NumberParameters >= 2) {
            const auto target_lr =
                reinterpret_cast<void*>(pExp->ExceptionRecord->ExceptionInformation[1]);
            const bool is_write = pExp->ExceptionRecord->ExceptionInformation[0] == 1;
            MEMORY_BASIC_INFORMATION mbi_lr{};
            if (VirtualQuery(target_lr, &mbi_lr, sizeof(mbi_lr)) != 0 &&
                mbi_lr.State == MEM_COMMIT && (mbi_lr.Type & MEM_MAPPED) != 0 &&
                (mbi_lr.Protect == PAGE_NOACCESS ||
                 (is_write && (mbi_lr.Protect == PAGE_READONLY ||
                               mbi_lr.Protect == PAGE_EXECUTE_READ)))) {
                // Only relax the single 16KB page containing the fault —
                // whole-region changes corrupt VMA bookkeeping for adjacent
                // guest mappings (VirtualQuery coalesces them).
                DWORD old_protect = 0;
                const auto page_base = reinterpret_cast<void*>(
                    (reinterpret_cast<u64>(target_lr)) & ~0x3FFFULL);
                if (VirtualProtect(page_base, 0x4000, PAGE_READWRITE, &old_protect)) {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
        LOG_CRITICAL(Debug, "Unhandled Exception code {:#x} at {}", code, address);
        // Record directly to file - the process may die during unwind.
        {
            HANDLE f = OpenCrashReportFile();
            if (f != INVALID_HANDLE_VALUE) {
                SetFilePointer(f, 0, nullptr, FILE_END);
                char line[2048];
                const auto* r = pExp->ExceptionRecord;
                const auto* c = pExp->ContextRecord;
                int n = 0;
                if (code == 0xC0000005 && r->NumberParameters >= 2) {
                    n = _snprintf(line, sizeof(line),
                                  "UNHANDLED_GUEST_FAULT code=%#llx rip=%p access=%#llx "
                                  "target=%#llx rax=%#llx rcx=%#llx rdx=%#llx rbx=%#llx rsp=%p "
                                  "rbp=%p\n",
                                  (unsigned long long)code, address,
                                  (unsigned long long)r->ExceptionInformation[0],
                                  (unsigned long long)r->ExceptionInformation[1],
                                  (unsigned long long)(c ? c->Rax : 0),
                                  (unsigned long long)(c ? c->Rcx : 0),
                                  (unsigned long long)(c ? c->Rdx : 0),
                                  (unsigned long long)(c ? c->Rbx : 0),
                                  (void*)(c ? c->Rsp : 0), (void*)(c ? c->Rbp : 0));
                    // Append protection info for rsp and target.
                    if (n > 0 && n < (int)sizeof(line) - 400 && c) {
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (VirtualQuery((void*)c->Rsp, &mbi, sizeof(mbi))) {
                            n += _snprintf(line + n, sizeof(line) - n - 1,
                                           "  RSPMEM base=%p size=%llx prot=%lx state=%lx "
                                           "type=%lx\n",
                                           mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                                           mbi.Protect, mbi.State, mbi.Type);
                        }
                        if (VirtualQuery((void*)r->ExceptionInformation[1], &mbi,
                                         sizeof(mbi))) {
                            n += _snprintf(line + n, sizeof(line) - n - 1,
                                           "  TGTMEM base=%p size=%llx prot=%lx state=%lx "
                                           "type=%lx\n",
                                           mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                                           mbi.Protect, mbi.State, mbi.Type);
                        }
                        // Dump bytes around the faulting RIP for offline
                        // disassembly.
                        __try {
                            n += _snprintf(line + n, sizeof(line) - n - 1, "  CODE");
                            const u8* rip8 = (const u8*)address;
                            for (int b = -8; b < 16; ++b) {
                                n += _snprintf(line + n, sizeof(line) - n - 1, "%02x",
                                               *(u8*)(rip8 + b));
                            }
                            // Identify the host thread via its start address.
                            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                            if (ntdll != nullptr) {
                                using NtQIT_t = LONG(WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
                                static NtQIT_t NtQIT = (NtQIT_t)GetProcAddress(
                                    ntdll, "NtQueryInformationThread");
                                if (NtQIT != nullptr) {
                                    void* start_addr = nullptr;
                                    if (NtQIT(GetCurrentThread(),
                                              9 /*ThreadQuerySetWin32Startaddress*/,
                                              &start_addr, sizeof(start_addr),
                                              nullptr) == 0 &&
                                        start_addr != nullptr) {
                                        n += _snprintf(line + n, sizeof(line) - n - 1,
                                                       " THRSTART=%p", start_addr);
                                    }
                                }
                            }
                            n += _snprintf(line + n, sizeof(line) - n - 1, "\n");
                        } __except (1) {
                            n += _snprintf(line + n, sizeof(line) - n - 1, "  (code unreadable)\n");
                        }
                    }
                } else if (code == 0xE06D7363 && r->NumberParameters >= 3) {
                    n = _snprintf(line, sizeof(line),
                                  "UNHANDLED_CPPTHROW addr=%p obj=%p throwinfo=%p\n", address,
                                  (void*)r->ExceptionInformation[1],
                                  (void*)r->ExceptionInformation[2]);
                    // Scan the stack for host module frames to find the thrower.
                    if (c != nullptr) {
                        HMODULE ntdll2 = GetModuleHandleW(L"ntdll.dll");
                        HMODULE exe2 = nullptr;
                        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           nullptr, &exe2);
                        using NtQIT_t = LONG(WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
                        static NtQIT_t NtQIT2 =
                            ntdll2 ? (NtQIT_t)GetProcAddress(ntdll2, "NtQueryInformationThread")
                                   : nullptr;
                        void* start_addr = nullptr;
                        if (NtQIT2 != nullptr) {
                            NtQIT2(GetCurrentThread(), 9, &start_addr, sizeof(start_addr),
                                   nullptr);
                        }
                        n += _snprintf(line + n, sizeof(line) - n - 1, "  THRSTART=%p\n",
                                       start_addr);
                        const unsigned long long* sp2 =
                            reinterpret_cast<unsigned long long*>(c->Rsp);
                        int shown = 0;
                        for (int i = 0; i < 2048 && shown < 20; ++i) {
                            __try {
                                const unsigned long long v = sp2[i];
                                HMODULE m = nullptr;
                                if (GetModuleHandleExW(
                                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        (LPCWSTR)v, &m) &&
                                    m != nullptr) {
                                    wchar_t wpath[260];
                                    const DWORD wl = GetModuleFileNameW(m, wpath, 260);
                                    const wchar_t* fname = wpath + wl;
                                    while (fname > wpath && *(fname - 1) != L'\\') {
                                        --fname;
                                    }
                                    char nb[64];
                                    int k = 0;
                                    while (*fname != L'\0' && k < 60) {
                                        nb[k++] = (char)*fname++;
                                    }
                                    nb[k] = '\0';
                                    n += _snprintf(line + n, sizeof(line) - n - 1,
                                                   "  frame %s+%llx\n", nb,
                                                   (unsigned long long)(v -
                                                                        (unsigned long long)m));
                                    ++shown;
                                }
                            } __except (1) {
                                break;
                            }
                        }
                    }
                } else {
                    n = _snprintf(line, sizeof(line),
                                  "UNHANDLED_GUEST_FAULT code=%#llx addr=%p\n",
                                  (unsigned long long)code, address);
                }
                DWORD written = 0;
                WriteFile(f, line, n, &written, nullptr);
                CloseHandle(f);
            }
        }
        Common::Singleton<Core::Emulator>::Instance()->Shutdown();
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#else

static std::string DisassembleInstruction(void* code_address) {
    char buffer[256] = "<unable to decode>";

#ifdef ARCH_X86_64
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    const auto status =
        Common::Decoder::Instance()->decodeInstruction(instruction, operands, code_address);
    if (ZYAN_SUCCESS(status)) {
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                        instruction.operand_count_visible, buffer, sizeof(buffer),
                                        reinterpret_cast<u64>(code_address), ZYAN_NULL);
    }
#endif

    return buffer;
}

static s32 NativeSiCodeToGuest(s32 sig, s32 code) {
    using namespace Libraries::Kernel;
    switch (sig) {
    case SIGUSR1:
        return POSIX_SI_LWP;
    case SIGSEGV:
        switch (code) {
        case SEGV_MAPERR:
            return POSIX_SEGV_MAPERR;
        case SEGV_ACCERR:
            return POSIX_SEGV_ACCERR;
        }
    case SIGBUS:
        switch (code) {
        case BUS_ADRALN:
            return POSIX_BUS_ADRALN;
        case BUS_ADRERR:
            return POSIX_BUS_ADRERR;
        case BUS_OBJERR:
            return POSIX_BUS_OBJERR;
        }
    case SIGILL:
        switch (code) {
        case ILL_ILLOPC:
            return POSIX_ILL_ILLOPC;
        case ILL_ILLOPN:
            return POSIX_ILL_ILLOPN;
        case ILL_ILLADR:
            return POSIX_ILL_ILLADR;
        case ILL_ILLTRP:
            return POSIX_ILL_ILLTRP;
        case ILL_PRVOPC:
            return POSIX_ILL_PRVOPC;
        case ILL_PRVREG:
            return POSIX_ILL_PRVREG;
        case ILL_COPROC:
            return POSIX_ILL_COPROC;
        case ILL_BADSTK:
            return POSIX_ILL_BADSTK;
        }
    case SIGFPE:
        switch (code) {
        case FPE_INTOVF:
            return POSIX_FPE_INTOVF;
        case FPE_INTDIV:
            return POSIX_FPE_INTDIV;
        case FPE_FLTDIV:
            return POSIX_FPE_FLTDIV;
        case FPE_FLTOVF:
            return POSIX_FPE_FLTOVF;
        case FPE_FLTUND:
            return POSIX_FPE_FLTUND;
        case FPE_FLTRES:
            return POSIX_FPE_FLTRES;
        case FPE_FLTINV:
            return POSIX_FPE_FLTINV;
        case FPE_FLTSUB:
            return POSIX_FPE_FLTSUB;
        }
    case SIGTRAP:
        switch (code) {
        case TRAP_BRKPT:
            return POSIX_TRAP_BRKPT;
        case TRAP_TRACE:
            return POSIX_TRAP_TRACE;
#ifdef __FreeBSD__
        case TRAP_DTRACE:
            return POSIX_TRAP_DTRACE;
#endif
        }

    default:
        return POSIX_SI_NOINFO;
    }
}

void SignalHandler(int sig, siginfo_t* info, void* raw_context) {
    using namespace Libraries::Kernel;
    auto* thread = g_curthread;
    const auto* signals = Signals::Instance();

    auto* code_address = Common::GetRip(raw_context);

    Ucontext context{info, reinterpret_cast<ucontext_t*>(raw_context)};
    Siginfo guest_info{};
    if (info) {
        guest_info = *reinterpret_cast<Siginfo*>(info);
        guest_info._si_signo = sig == SIGUSR1 ? 0 : NativeToOrbisSignal(info->si_signo);
        guest_info._si_errno = NativeToPosixErrno(info->si_errno);
        guest_info._si_code = NativeSiCodeToGuest(sig, info->si_code);
        guest_info._si_addr = (void*)context.uc_mcontext.mc_rip;
    }
    Siginfo* info_p = info ? &guest_info : nullptr;
    Ucontext* context_p = raw_context ? &context : nullptr;

    switch (sig) {
    case SIGSEGV:
    case SIGBUS: {
        const bool is_write = Common::IsWriteError(raw_context);
        if (!signals->DispatchAccessViolation(raw_context, info->si_addr)) {
            if (thread && thread->DispatchSignal(NativeToOrbisSignal(sig), info_p, context_p)) {
                return;
            }
            UNREACHABLE_MSG("Unhandled access violation at code address {}: {} address {}",
                            fmt::ptr(code_address), is_write ? "Write to" : "Read from",
                            fmt::ptr(info->si_addr));
        }
        break;
    }
    case SIGILL:
        if (signals->DispatchIllegalInstruction(raw_context)) {
            return;
        }
    case SIGFPE:
    case SIGTRAP:
    case SIGSYS: {
        if (thread && thread->DispatchSignal(NativeToOrbisSignal(sig), info_p, context_p)) {
            return;
        }

        UNREACHABLE_MSG("Unhandled signal {} at code address {}", sig, fmt::ptr(code_address));
    }
    case SIGSLEEP: {
        // Sleep thread until signal is received again
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGSLEEP);
        sigwait(&sigset, &sig);
        break;
    }
    case SIGUSR1:
        if (thread) {
            thread->DispatchPendingSignals(info_p, context_p);
        }
        break;
    default:
        UNREACHABLE_MSG("Unhandled signal {} at code address {}", sig, fmt::ptr(code_address));
    }
}

#endif

SignalDispatch::SignalDispatch() {
#if defined(_WIN32)
    ASSERT_MSG(handle = AddVectoredExceptionHandler(0, SignalHandler),
               "Failed to register exception handler.");
#else
    struct sigaction action{};
    action.sa_sigaction = SignalHandler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);

    ASSERT_MSG(
        sigaction(SIGSEGV, &action, nullptr) == 0 && sigaction(SIGBUS, &action, nullptr) == 0 &&
            sigaction(SIGILL, &action, nullptr) == 0 && sigaction(SIGFPE, &action, nullptr) == 0 &&
            sigaction(SIGTRAP, &action, nullptr) == 0 && sigaction(SIGSYS, &action, nullptr) == 0 &&
            sigaction(SIGUSR1, &action, nullptr) == 0 && sigaction(SIGSLEEP, &action, nullptr) == 0,
        "Failed to register signal handlers.");
#endif
}

void SignalDispatch::RemoveHandlers() {
    // asserting here would get into an infinite loop until too
    // many nested exceptions makes the OS kill the process
#if defined(_WIN32)
    if (!(RemoveVectoredExceptionHandler(handle))) {
        LOG_CRITICAL(Core, "Failed to remove exception handler.");
        std::quick_exit(1);
    }
#else
    struct sigaction action{};
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);

    if (!(sigaction(SIGSEGV, &action, nullptr) == 0 && sigaction(SIGBUS, &action, nullptr) == 0 &&
          sigaction(SIGILL, &action, nullptr) == 0 && sigaction(SIGFPE, &action, nullptr) == 0 &&
          sigaction(SIGTRAP, &action, nullptr) == 0 && sigaction(SIGSYS, &action, nullptr) == 0 &&
          sigaction(SIGUSR1, &action, nullptr) == 0 &&
          sigaction(SIGSLEEP, &action, nullptr) == 0)) {
        LOG_CRITICAL(Core, "Failed to remove signal handlers.");
        std::quick_exit(1);
    }
#endif
}

SignalDispatch::~SignalDispatch() {
    RemoveHandlers();
}

bool SignalDispatch::DispatchAccessViolation(void* context, void* fault_address) const {
    for (const auto& [handler, _] : access_violation_handlers) {
        if (handler(context, fault_address)) {
            return true;
        }
    }
    return false;
}

bool SignalDispatch::DispatchIllegalInstruction(void* context) const {
    for (const auto& [handler, _] : illegal_instruction_handlers) {
        if (handler(context)) {
            return true;
        }
    }
    return false;
}

} // namespace Core
