// SPDX-FileCopyrightText: Copyright 2025-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>
#include <CLI/CLI.hpp>
#include <SDL3/SDL_messagebox.h>
#ifdef _WIN32
#include <crtdbg.h>
#include <signal.h>
#include <stdlib.h>
#endif

#include "common/arch.h"
#include "common/key_manager.h"
#include "common/logging/log.h"
#include "common/memory_patcher.h"
#include "common/path_util.h"
#include "core/debugger.h"
#include "core/emulator_settings.h"
#include "core/emulator_state.h"
#include "core/file_sys/fs.h"
#include "core/ipc/ipc.h"
#include "core/user_settings.h"
#include "emulator.h"
#include "imgui/big_picture/big_picture.h"

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#ifdef _WIN32
static void Shadps4InvalidParameterHandler(const wchar_t* expression, const wchar_t* function,
                                            const wchar_t* file, unsigned int line,
                                            uintptr_t reserved) {
    LOG_ERROR(Common, "Invalid CRT parameter (game passed bad arguments); continuing");
}

// Diagnostics: file exit tracing is disabled unless SHADPS4_CRASH_REPORT is
// set (its value is the output path; "1" = crash_report.txt next to the exe).
static HANDLE OpenDiagFile() noexcept {
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

static void LogExitPath(const char* why) {
    // Append to crash report file so it survives even if spdlog is dead.
    HANDLE f = OpenDiagFile();
    if (f != INVALID_HANDLE_VALUE) {
        SetFilePointer(f, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(f, why, (DWORD)strlen(why), &written, nullptr);
        WriteFile(f, "\n", 1, &written, nullptr);
        CloseHandle(f);
    }
}

static void Shadps4TerminateHandler() {
    char msg[256];
    int n = _snprintf(msg, sizeof(msg), "EXIT_PATH: std::terminate: ");
    try {
        throw;
    } catch (const std::exception& e) {
        const char* w = e.what();
        while (*w != '\0' && n < (int)sizeof(msg) - 2) {
            msg[n++] = *w++;
        }
    } catch (...) {
        n += _snprintf(msg + n, sizeof(msg) - n - 1, "(non-std exception)");
    }
    msg[n] = '\n';
    msg[n + 1] = '\0';
    LogExitPath(msg);
    std::abort();
}

static void Shadps4PureVirtualCall() {
    LogExitPath("EXIT_PATH: pure virtual call");
    std::abort();
}

static void Shadps4Atexit() {
    LogExitPath("EXIT_PATH: atexit (exit() or normal shutdown)");
}

static void Shadps4SigAbrt(int sig) {
    // Capture the abort call stack for diagnosis.
    {
        void* frames[24];
        const USHORT n = CaptureStackBackTrace(0, 24, frames, nullptr);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        HANDLE h = OpenDiagFile();
        if (h != INVALID_HANDLE_VALUE) {
            SetFilePointer(h, 0, nullptr, FILE_END);
            DWORD written = 0;
            WriteFile(h, "EXIT_PATH: SIGABRT (abort called)\n", 34, &written, nullptr);
            for (USHORT i = 0; i < n; ++i) {
                char line[128];
                HMODULE m = nullptr;
                GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)frames[i], &m);
                const int ln = _snprintf(line, sizeof(line), "  ABORTFRAME %p (%s+%llx)\n",
                                         frames[i], m ? "module" : "no-module",
                                         m ? (unsigned long long)((u8*)frames[i] - (u8*)m)
                                           : 0ull);
                WriteFile(h, line, ln, &written, nullptr);
            }
            CloseHandle(h);
        }
    }
    _exit(3);
}
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    // Prevent MSVC secure CRT functions from silently terminating the process
    // when guest code passes invalid arguments (e.g. buffer too small).
    _set_invalid_parameter_handler(&Shadps4InvalidParameterHandler);
    _CrtSetReportMode(_CRT_ASSERT, 0);
    std::set_terminate(&Shadps4TerminateHandler);
    _set_purecall_handler(&Shadps4PureVirtualCall);
    atexit(&Shadps4Atexit);
    signal(SIGABRT, &Shadps4SigAbrt);
#endif

#if defined(__APPLE__) && defined(ARCH_X86_64)
    // KosmicKrisp only supports Apple Silicon. Check that we are not running on an Intel Mac.
    int sysctl_ret = 0;
    size_t sysctl_size = sizeof(sysctl_ret);
    sysctlbyname("sysctl.proc_translated", &sysctl_ret, &sysctl_size, nullptr, 0);
    if (sysctl_ret != 1) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "shadPS4",
                                 "shadPS4 only supports Apple Silicon Macs.", nullptr);
        std::cout << "shadPS4 only supports Apple Silicon Macs." << std::endl;
        return -1;
    }
#endif

    CLI::App app{"shadPS4 Emulator CLI"};

    // ---- CLI state ----
    std::optional<std::string> gamePath;
    std::vector<std::string> gameArgs;
    std::optional<std::filesystem::path> overrideRoot;
    std::optional<int> waitPid;
    bool waitForDebugger = false;
    bool userfaultfd = false;

    std::optional<std::string> fullscreenStr;
    bool ignoreGamePatch = false;
    bool showFps = false;
    bool configClean = false;
    bool configGlobal = false;
    bool bigPicture = false;
    bool sameProcess = false;

    std::optional<std::filesystem::path> addGameFolder;
    std::optional<std::filesystem::path> setAddonFolder;
    std::optional<std::string> patchFile;

    std::vector<std::pair<std::filesystem::path, std::string>> mounts;
    static std::vector<std::string> env_vars;

    // ---- Options ----
    app.add_option("guest_arg", gamePath, "Game path or ID"); // positional
    app.add_option("-g,--game", gamePath, "Game path or ID");
    app.add_option("-p,--patch", patchFile, "Patch file to apply");
    app.add_flag("-i,--ignore-game-patch", ignoreGamePatch,
                 "Disable automatic loading of game patches");

    app.add_flag("-b,--big-picture", bigPicture, "Start in Big Picture Mode");
    app.add_flag("--same-process", sameProcess,
                 "Launch the game in the same process when using Big Picture Mode");

    app.add_option("-f,--fullscreen", fullscreenStr, "Fullscreen mode (true|false)");

    app.add_option("--override-root", overrideRoot)->check(CLI::ExistingDirectory);

    app.add_flag("--wait-for-debugger", waitForDebugger);
    app.add_option("--wait-for-pid", waitPid);
#ifdef __linux__
    app.add_flag("--userfaultfd", userfaultfd,
                 "Enable userfaultfd for tracking memory (Linux only)");
#endif

    app.add_flag("--show-fps", showFps);
    app.add_flag("--config-clean", configClean);
    app.add_flag("--config-global", configGlobal);
    app.add_flag("--log-append", Common::Log::g_should_append);

    app.add_option("--add-game-folder", addGameFolder)->check(CLI::ExistingDirectory);
    app.add_option("--set-addon-folder", setAddonFolder)->check(CLI::ExistingDirectory);
    app.add_option("--mount", mounts, "Mount source to destination");
    app.add_option("-e,--env", env_vars, "Environment variables to pass to the guest");

    // ---- Capture args after `--` verbatim ----
    app.allow_extras();

    // ---- No-args behavior ----
    if (argc == 1) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "shadPS4",
                                 "This is a CLI application. Please use the '-b' flag for Big "
                                 "Picture mode, or QTLauncher for a standalone GUI:\n"
                                 "https://github.com/shadps4-emu/shadps4-qtlauncher/releases",
                                 nullptr);
        std::cout << app.help();
        return -1;
    }

    try {
        bool double_dash_found = false;
        int double_dash_index;
        for (int i = 0; i < argc; i++) {
            if (double_dash_found) {
                gameArgs.emplace_back(argv[i]);
            }
            if (!double_dash_found && std::string(argv[i]) == "--") {
                double_dash_found = true;
                double_dash_index = i;
            }
        }

        // If the -- arg is present, only parse args before it
        if (double_dash_found) {
            app.parse(double_dash_index, argv);
        } else {
            app.parse(argc, argv);
        }
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (waitPid)
        Core::Debugger::WaitForPid(*waitPid);

    // Initialize main log with default config
    Common::Log::Setup("shadps4.log");

    LOG_INFO(Debug, "Run: {}", std::span(argv, argc));

    IPC::Instance().Init();

    auto emu_state = std::make_shared<EmulatorState>();
    EmulatorState::SetInstance(emu_state);
    UserSettings.Load();

    // Initialize key manager
    auto key_manager = KeyManager::GetInstance();
    key_manager->LoadFromFile();

    // Load configurations
    std::shared_ptr<EmulatorSettingsImpl> emu_settings = std::make_shared<EmulatorSettingsImpl>();
    EmulatorSettingsImpl::SetInstance(emu_settings);
    emu_settings->Load();

    // Configure logger appropriately
    Common::Log::g_should_append |= EmulatorSettings.IsLogAppend();

    if (bigPicture) {
        BigPictureMode::Launch(argv[0], sameProcess);
        return 0;
    }

    // ---- Utility commands ----
    if (addGameFolder) {
        EmulatorSettings.AddGameInstallDir(*addGameFolder);
        EmulatorSettings.Save();
        LOG_INFO(Config, "Game folder successfully saved.");
        return 0;
    }

    if (setAddonFolder) {
        EmulatorSettings.SetAddonInstallDir(*setAddonFolder);
        EmulatorSettings.Save();
        LOG_INFO(Config, "Addon folder successfully saved.");
        return 0;
    }

    if (!gamePath.has_value()) {
        if (!gameArgs.empty()) {
            gamePath = gameArgs.front();
            gameArgs.erase(gameArgs.begin());
        } else {
            LOG_ERROR(Debug, "Please provide a game path or ID.");
            return 1;
        }
    }

    // ---- Apply flags ----
    if (patchFile)
        MemoryPatcher::patch_file = *patchFile;

    if (ignoreGamePatch)
        Core::FileSys::MntPoints::ignore_game_patches = true;

    if (fullscreenStr) {
        if (*fullscreenStr == "true") {
            EmulatorSettings.SetFullScreen(true);
        } else if (*fullscreenStr == "false") {
            EmulatorSettings.SetFullScreen(false);
        } else {
            LOG_ERROR(Debug, "Invalid argument for --fullscreen (use true|false)");
            return 1;
        }
    }

    if (showFps)
        EmulatorSettings.SetShowFpsCounter(true);

    if (configClean)
        EmulatorSettings.SetConfigMode(ConfigMode::Clean);

    if (configGlobal)
        EmulatorSettings.SetConfigMode(ConfigMode::Global);

    if (userfaultfd) {
        EmulatorSettings.SetUserfaultfdTracking(true);
    }

    // ---- Resolve game path or ID ----
    std::filesystem::path ebootPath(*gamePath);
    const auto archive_component_exists = [](const std::filesystem::path& p) -> bool {
        std::filesystem::path accum;
        for (const auto& comp : p) {
            accum /= comp;
            if (comp.extension() == ".zar") {
                return std::filesystem::is_regular_file(accum);
            }
        }
        return false;
    };
    if (!std::filesystem::exists(ebootPath) && !archive_component_exists(ebootPath)) {
        bool found = false;
        constexpr int maxDepth = 5;
        for (const auto& installDir : EmulatorSettings.GetGameInstallDirs()) {
            if (auto foundPath = Common::FS::FindGameByID(installDir, *gamePath, maxDepth)) {
                ebootPath = *foundPath;
                found = true;
                break;
            }
        }
        if (!found) {
            LOG_ERROR(Debug, "Game ID or file path not found: {}", *gamePath);
            return 1;
        }
    }

    auto* emulator = Common::Singleton<Core::Emulator>::Instance();
    emulator->executableName = argv[0];
    emulator->waitForDebuggerBeforeRun = waitForDebugger;
    emulator->Run(ebootPath, gameArgs, overrideRoot, mounts, env_vars);

    return 0;
}
