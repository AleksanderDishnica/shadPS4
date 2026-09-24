// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/assert.h"
#include "common/logging/formatter.h"
#include "core/emulator_settings.h"
#include "video_core/renderdoc.h"

#include <atomic>
#include <renderdoc_app.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <filesystem>

namespace VideoCore {

enum class CaptureState {
    Idle,
    Triggered,
    InProgress,
};
static CaptureState capture_state{CaptureState::Idle};
static std::atomic<u32> screenshot_game_only_count{0};
static std::atomic<u32> screenshot_with_overlays_count{0};

static void* capture_device{};
static void* capture_window{};

void SetCaptureTarget(void* device, void* window) {
    capture_device = device;
    capture_window = window;
    LOG_WARNING(Common, "RenderDoc capture target: device={:p} window={:p}", device, window);
}

RENDERDOC_API_1_6_0* rdoc_api{};

void LoadRenderDoc() {
#ifdef _WIN32

    // Check if we are running by RDoc GUI
    HMODULE mod = GetModuleHandleA("renderdoc.dll");
    if (!mod && EmulatorSettings.IsRenderdocEnabled()) {
        // If enabled in config, try to load RDoc runtime in offline mode.
        // The Vulkan capture layer (activated via VK_INSTANCE_LAYERS /
        // VK_LAYER_PATH) is the authoritative instance: load the same DLL so
        // the capture API connects to it.
        char layer_path[MAX_PATH]{};
        size_t layer_len = 0;
        if (getenv_s(&layer_len, layer_path, sizeof(layer_path) - MAX_PATH / 2,
                     "VK_LAYER_PATH") == 0 &&
            layer_len > 0) {
            std::string lib = std::string(layer_path) + "\\renderdoc.dll";
            mod = LoadLibraryA(lib.c_str());
        }
        if (mod == nullptr) {
            mod = LoadLibraryA("renderdoc.dll");
        }
        if (mod == nullptr) {
            LOG_WARNING(Render, "Direct renderdoc.dll load failed (err={}); trying registry",
                        GetLastError());
        }
    }
    if (!mod && EmulatorSettings.IsRenderdocEnabled()) {
        HKEY h_reg_key;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Classes\\RenderDoc.RDCCapture.1\\DefaultIcon\\", 0,
                                    KEY_READ, &h_reg_key);
        if (result != ERROR_SUCCESS) {
            LOG_WARNING(Render, "RenderDoc enabled but runtime not found");
            return;
        }
        std::array<wchar_t, MAX_PATH> key_str{};
        DWORD str_sz_out{key_str.size()};
        result = RegQueryValueExW(h_reg_key, L"", 0, NULL, (LPBYTE)key_str.data(), &str_sz_out);
        if (result != ERROR_SUCCESS) {
            return;
        }

        std::filesystem::path path{key_str.cbegin(), key_str.cend()};
        path = path.parent_path().append("renderdoc.dll");
        const auto path_to_lib = path.generic_string();
        mod = LoadLibraryA(path_to_lib.c_str());
    }

    if (mod) {
        const auto RENDERDOC_GetAPI =
            reinterpret_cast<pRENDERDOC_GetAPI>(GetProcAddress(mod, "RENDERDOC_GetAPI"));
        const s32 ret = RENDERDOC_GetAPI(eRENDERDOC_API_Version_1_6_0, (void**)&rdoc_api);
        ASSERT(ret == 1);
    }
#else
#ifdef ANDROID
    static constexpr const char RENDERDOC_LIB[] = "libVkLayer_GLES_RenderDoc.so";
#else
    static constexpr const char RENDERDOC_LIB[] = "librenderdoc.so";
#endif
    // Check if we are running by RDoc GUI
    void* mod = dlopen(RENDERDOC_LIB, RTLD_NOW | RTLD_NOLOAD);
    if (!mod && EmulatorSettings.IsRenderdocEnabled()) {
        // If enabled in config, try to load RDoc runtime in offline mode
        if ((mod = dlopen(RENDERDOC_LIB, RTLD_NOW))) {
            const auto RENDERDOC_GetAPI =
                reinterpret_cast<pRENDERDOC_GetAPI>(dlsym(mod, "RENDERDOC_GetAPI"));
            const s32 ret = RENDERDOC_GetAPI(eRENDERDOC_API_Version_1_6_0, (void**)&rdoc_api);
            ASSERT(ret == 1);
        } else {
            LOG_ERROR(Render, "Cannot load RenderDoc: {}", dlerror());
        }
    }
#endif
    if (rdoc_api) {
        LOG_INFO(Render, "RenderDoc API loaded (offline capture available)");
        // Keep RenderDoc's default capture hotkey (F12) enabled so captures
        // can be triggered externally; it captures at the next present and
        // writes the file itself.

        // Also remove rdoc crash handler
        rdoc_api->UnloadCrashHandler();
    } else if (EmulatorSettings.IsRenderdocEnabled()) {
        LOG_WARNING(Render, "RenderDoc enabled but API not loaded (renderdoc.dll not found)");
    }
}

void StartCapture() {
    if (!rdoc_api) {
        return;
    }

    if (capture_state == CaptureState::Triggered) {
        rdoc_api->StartFrameCapture(capture_device, capture_window);
        capture_state = CaptureState::InProgress;
    }
}

void EndCapture() {
    if (!rdoc_api) {
        return;
    }

    if (capture_state == CaptureState::InProgress) {
        rdoc_api->EndFrameCapture(capture_device, capture_window);
        capture_state = CaptureState::Idle;
    }
}

void TriggerCapture() {
    if (capture_state == CaptureState::Idle) {
        capture_state = CaptureState::Triggered;
    }
}

void SetOutputDir(const std::filesystem::path& path, const std::string& prefix) {
    if (!rdoc_api) {
        return;
    }
    LOG_WARNING(Common, "RenderDoc capture path: {}", (path / prefix).string());
    rdoc_api->SetCaptureFilePathTemplate(fmt::UTF((path / prefix).u8string()).data.data());
}

bool IsRenderDocLoaded() {
    return rdoc_api != nullptr;
}

RENDERDOC_API_1_6_0* GetRenderDocAPI() {
    return rdoc_api;
}

void RequestScreenshot(const ScreenshotRequest request) {
    switch (request) {
    case ScreenshotRequest::GameOnly:
        screenshot_game_only_count.fetch_add(1, std::memory_order_relaxed);
        break;
    case ScreenshotRequest::WithOverlays:
        screenshot_with_overlays_count.fetch_add(1, std::memory_order_relaxed);
        break;
    case ScreenshotRequest::None:
    default:
        break;
    }
}

u32 ConsumeGameOnlyScreenshotRequests() {
    return screenshot_game_only_count.exchange(0, std::memory_order_acq_rel);
}

u32 ConsumeWithOverlaysScreenshotRequests() {
    return screenshot_with_overlays_count.exchange(0, std::memory_order_acq_rel);
}

ScreenshotRequests ConsumeScreenshotRequests() {
    return ScreenshotRequests{
        .game_only_count = ConsumeGameOnlyScreenshotRequests(),
        .with_overlays_count = ConsumeWithOverlaysScreenshotRequests(),
    };
}

} // namespace VideoCore
