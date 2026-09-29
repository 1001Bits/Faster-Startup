#include "ProgressPanel.h"
#include <algorithm>
#include <cstdio>

namespace startup {
namespace {
constexpr wchar_t windowClass[] = L"FasterStartup.Progress.1";
const wchar_t* label(ProgressPhase phase) noexcept {
    switch (phase) {
    case ProgressPhase::checking: return L"Checking cached file information";
    case ProgressPhase::indexing: return L"Building the source index";
    case ProgressPhase::loading: return L"Reading validated cache";
    case ProgressPhase::capturing: return L"Preparing startup cache";
    case ProgressPhase::saving: return L"Saving startup cache";
    default: return L"Startup cache finished";
    }
}
void fill(HDC dc, RECT rect, COLORREF color) noexcept {
    const auto brush = CreateSolidBrush(color);
    if (brush) { FillRect(dc, &rect, brush); DeleteObject(brush); }
}
struct GameWindow { HWND panel{}, game{}; LONG area{}; };
BOOL CALLBACK findGame(HWND window, LPARAM parameter) noexcept {
    auto& found = *reinterpret_cast<GameWindow*>(parameter);
    DWORD process{}; GetWindowThreadProcessId(window, &process);
    if (window == found.panel || process != GetCurrentProcessId() || !IsWindowVisible(window) ||
        (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOOLWINDOW)) return TRUE;
    RECT rect{};
    if (GetClientRect(window, &rect)) {
        const LONG area = (rect.right - rect.left) * (rect.bottom - rect.top);
        if (area > found.area) { found.game = window; found.area = area; }
    }
    return TRUE;
}
}

ProgressPanel::~ProgressPanel() { stop(); if (thread_.joinable()) thread_.join(); }
void ProgressPanel::start() noexcept {
    if (!state_ || state_->snapshot().terminal || started_.exchange(true)) return;
    if (!state_->snapshot().started) state_->phase(ProgressPhase::checking);
    try { thread_ = std::thread([this] { run(); }); }
    catch (...) { stopping_ = true; } // Progress is optional; enumeration stays usable.
}
void ProgressPanel::stop() noexcept {
    stopping_ = true;
    if (const auto window = window_.load()) PostMessageW(window, WM_CLOSE, 0, 0);
}
void ProgressPanel::position(HWND window) noexcept {
    GameWindow found{window}; EnumWindows(findGame, reinterpret_cast<LPARAM>(&found));
    RECT target{};
    if (found.game) {
        DWORD foreground{}; GetWindowThreadProcessId(GetForegroundWindow(), &foreground);
        if (IsIconic(found.game) || (foreground && foreground != GetCurrentProcessId())) {
            ShowWindow(window, SW_HIDE); return;
        }
        if (!GetWindowRect(found.game, &target)) return;
    } else {
        MONITORINFO monitor{sizeof(monitor)};
        if (!GetMonitorInfoW(MonitorFromWindow(GetForegroundWindow(), MONITOR_DEFAULTTOPRIMARY), &monitor)) return;
        target = monitor.rcWork;
    }
    const int x = target.left + (target.right - target.left - width_) / 2;
    const int y = target.top + std::max(0L, (target.bottom - target.top - height_) / 2);
    SetWindowPos(window, HWND_TOPMOST, x, y, width_, height_, SWP_NOACTIVATE | SWP_SHOWWINDOW);
}
void ProgressPanel::paint(HWND window, HDC destination) noexcept {
    PAINTSTRUCT paint{}; const auto target = destination ? destination : BeginPaint(window, &paint);
    if (!target) return;
    const auto dc = CreateCompatibleDC(target);
    const auto bitmap = CreateCompatibleBitmap(target, width_, height_);
    if (!dc || !bitmap) {
        if (dc) DeleteDC(dc); if (bitmap) DeleteObject(bitmap);
        if (!destination) EndPaint(window, &paint);
        return;
    }
    const auto previous = SelectObject(dc, bitmap);
    fill(dc, {0, 0, width_, height_}, RGB(26, 29, 35));
    fill(dc, {0, 0, width_, 3}, RGB(79, 157, 244));
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(234, 239, 245));
    const auto oldFont = SelectObject(dc, titleFont_);
    RECT title{20, 16, width_ - 20, 40};
    DrawTextW(dc, L"Faster Startup", -1, &title, DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(dc, bodyFont_);
    const auto progress = state_->snapshot();
    RECT phase{20, 47, width_ - 20, 68};
    DrawTextW(dc, label(progress.phase), -1, &phase, DT_SINGLELINE | DT_NOPREFIX);
    RECT track{20, 80, width_ - 20, 88}; fill(dc, track, RGB(48, 54, 64));
    auto bar = track;
    if (progress.total) {
        bar.right = bar.left + static_cast<LONG>((track.right - track.left) *
            (double(std::min(progress.completed, progress.total)) / double(progress.total)));
    } else {
        const LONG span = (track.right - track.left) / 4;
        const auto step = static_cast<LONG>((GetTickCount64() / 12) % (2 * (track.right - track.left - span)));
        bar.left += std::min(step, 2 * (track.right - track.left - span) - step);
        bar.right = bar.left + span;
    }
    fill(dc, bar, RGB(79, 157, 244));
    wchar_t details[192]{};
    if (progress.phase == ProgressPhase::indexing)
        swprintf_s(details, L"%llu files  /  %llu folders     %.1f s", progress.files, progress.directories, progress.elapsedMs / 1000.0);
    else if (progress.total)
        swprintf_s(details, L"%llu / %llu folders     %.1f s", std::min(progress.completed, progress.total), progress.total, progress.elapsedMs / 1000.0);
    else swprintf_s(details, L"Please wait while the game starts     %.1f s", progress.elapsedMs / 1000.0);
    SetTextColor(dc, RGB(158, 170, 189));
    RECT detail{20, 103, width_ - 20, height_ - 12};
    DrawTextW(dc, details, -1, &detail, DT_SINGLELINE | DT_NOPREFIX);
    BitBlt(target, 0, 0, width_, height_, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldFont); SelectObject(dc, previous); DeleteObject(bitmap); DeleteDC(dc);
    if (!destination) EndPaint(window, &paint);
}
LRESULT CALLBACK ProgressPanel::procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
    auto* panel = reinterpret_cast<ProgressPanel*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        panel = static_cast<ProgressPanel*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    }
    if (!panel) return DefWindowProcW(window, message, wparam, lparam);
    switch (message) {
    case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
    case WM_NCHITTEST: return HTTRANSPARENT;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: panel->paint(window); return 0;
    case WM_PRINTCLIENT: panel->paint(window, reinterpret_cast<HDC>(wparam)); return 0;
    case WM_TIMER:
        if (panel->stopping_ || panel->state_->snapshot().terminal) DestroyWindow(window);
        else { panel->position(window); InvalidateRect(window, nullptr, FALSE); }
        return 0;
    case WM_CLOSE: DestroyWindow(window); return 0;
    case WM_DESTROY: panel->window_ = nullptr; PostQuitMessage(0); return 0;
    default: return DefWindowProcW(window, message, wparam, lparam);
    }
}
void ProgressPanel::run() noexcept {
    // Only a launch that builds the cache shows progress; a warm launch never
    // does. The delay avoids flashing a window for a short rebuild.
    const auto began = GetTickCount64();
    for (;;) {
        const auto progress = state_->snapshot();
        if (stopping_ || progress.terminal) return;
        if (progress.building && GetTickCount64() - began >= delayMs_) break;
        Sleep(25);
    }
    HMODULE module{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&procedure), &module)) return;
    WNDCLASSEXW type{sizeof(type)}; type.lpfnWndProc = procedure; type.hInstance = module; type.lpszClassName = windowClass;
    if (!RegisterClassExW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return;
    titleFont_ = CreateFontW(-18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    bodyFont_ = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    const auto window = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TRANSPARENT,
        windowClass, L"Faster Startup", WS_POPUP, 0, 0, width_, height_, nullptr, nullptr, module, this);
    if (window) {
        window_ = window;
        if (SetLayeredWindowAttributes(window, 0, 245, LWA_ALPHA) && SetTimer(window, 1, 100, nullptr)) {
            position(window);
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        if (IsWindow(window)) DestroyWindow(window);
        window_ = nullptr;
    }
    if (titleFont_) DeleteObject(titleFont_);
    if (bodyFont_) DeleteObject(bodyFont_);
    UnregisterClassW(windowClass, module);
}
}
