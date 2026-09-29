#pragma once
#include "Progress.h"
#include <atomic>
#include <memory>
#include <thread>

namespace startup {
// A passive, DLL-owned desktop window. No rendering hooks, graphics device,
// injected input, helper executable, or VR compositor overlay.
class ProgressPanel {
public:
    explicit ProgressPanel(std::shared_ptr<ProgressState> state, unsigned delayMs = 700) :
        state_(std::move(state)), delayMs_(delayMs) {}
    ~ProgressPanel(); // Test/tool lifetime; the plugin retains this until exit.
    void start() noexcept;
    void stop() noexcept;
    HWND window() const noexcept { return window_.load(); }
private:
    void run() noexcept;
    void position(HWND window) noexcept;
    void paint(HWND window, HDC destination = nullptr) noexcept;
    static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept;
    std::shared_ptr<ProgressState> state_;
    unsigned delayMs_;
    std::atomic<bool> started_{false}, stopping_{false};
    std::atomic<HWND> window_{nullptr};
    std::thread thread_;
    HFONT titleFont_{}, bodyFont_{};
    int width_ = 480, height_ = 150;
};
}
