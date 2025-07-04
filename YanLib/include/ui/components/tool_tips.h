/* clang-format off */
/*
 * @file tool_tips.h
 * @date 2025-06-02
 * @license MIT License
 *
 * Copyright (c) 2025 BinRacer <native.lab@outlook.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* clang-format on */
#ifndef TOOL_TIPS_H
#define TOOL_TIPS_H
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <Windows.h>
#include <CommCtrl.h>
#include <minwindef.h>
#include <windef.h>
#include <WinUser.h>
#include <cstdint>
#include <string>
#include <vector>
#include "sync/rwlock.h"
#include "helper/convert.h"
#include "ui/core/core.h"
#include "components.h"
#pragma comment(lib, "ComCtl32.Lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "User32.Lib")
namespace YanLib::ui::components {
    class tool_tips {
    private:
        std::vector<HWND> tool_tips_handles = {};
        sync::rwlock tool_tips_rwlock = {};
        uint32_t error_code = 0;

    public:
        tool_tips(const tool_tips &other) = delete;

        tool_tips(tool_tips &&other) = delete;

        tool_tips &operator=(const tool_tips &other) = delete;

        tool_tips &operator=(tool_tips &&other) = delete;

        tool_tips();

        ~tool_tips();

        HWND create(HWND parent_window_handle,
                    LPARAM lparam,
                    int32_t x = CW_USEDEFAULT,
                    int32_t y = CW_USEDEFAULT,
                    int32_t width = CW_USEDEFAULT,
                    int32_t height = CW_USEDEFAULT,
                    ToolTipStyle style = ToolTipStyle::AlwaysTip |
                            ToolTipStyle::Balloon | ToolTipStyle::Close,
                    core::WindowStyle window_style = core::WindowStyle::Popup);

        HWND create(const char *tool_tips_name,
                    HWND parent_window_handle,
                    LPARAM lparam,
                    int32_t x = CW_USEDEFAULT,
                    int32_t y = CW_USEDEFAULT,
                    int32_t width = CW_USEDEFAULT,
                    int32_t height = CW_USEDEFAULT,
                    ToolTipStyle style = ToolTipStyle::AlwaysTip |
                            ToolTipStyle::Balloon | ToolTipStyle::Close,
                    core::WindowStyle window_style = core::WindowStyle::Popup);

        HWND create(const wchar_t *tool_tips_name,
                    HWND parent_window_handle,
                    LPARAM lparam,
                    int32_t x = CW_USEDEFAULT,
                    int32_t y = CW_USEDEFAULT,
                    int32_t width = CW_USEDEFAULT,
                    int32_t height = CW_USEDEFAULT,
                    ToolTipStyle style = ToolTipStyle::AlwaysTip |
                            ToolTipStyle::Balloon | ToolTipStyle::Close,
                    core::WindowStyle window_style = core::WindowStyle::Popup);

        bool destroy(HWND tool_tips_handle);

        void activate(HWND tool_tips_handle);

        void deactivate(HWND tool_tips_handle);

        // if flag contains TTF_IDISHWND, id must be tool_tips_handle
        TTTOOLINFOA make_info(uintptr_t id,
                              HWND parent_window_handle,
                              HINSTANCE instance_handle,
                              RECT rect,
                              std::string &text,
                              LPARAM lparam,
                              TTInfoFlag flag);

        // if flag contains TTF_IDISHWND, id must be tool_tips_handle
        TTTOOLINFOW make_info(uintptr_t id,
                              HWND parent_window_handle,
                              HINSTANCE instance_handle,
                              RECT rect,
                              std::wstring &text,
                              LPARAM lparam,
                              TTInfoFlag flag);

        void activate_track(HWND tool_tips_handle, TTTOOLINFOW *tool_tips);

        void deactivate_track(HWND tool_tips_handle, TTTOOLINFOW *tool_tips);

        void set_track_pos(HWND tool_tips_handle, POINT point);

        bool add_tool(HWND tool_tips_handle, TTTOOLINFOA *tool_tips);

        bool add_tool(HWND tool_tips_handle, TTTOOLINFOW *tool_tips);

        void delete_tool(HWND tool_tips_handle, TTTOOLINFOA *tool_tips);

        void delete_tool(HWND tool_tips_handle, TTTOOLINFOW *tool_tips);

        bool
        enum_tool(HWND tool_tips_handle, int64_t index, TTTOOLINFOA *tool_info);

        bool
        enum_tool(HWND tool_tips_handle, int64_t index, TTTOOLINFOW *tool_info);

        int64_t get_tool_count(HWND tool_tips_handle);

        bool get_tool_info(HWND tool_tips_handle, TTTOOLINFOA *tool_info);

        bool get_tool_info(HWND tool_tips_handle, TTTOOLINFOW *tool_info);

        void set_tool_info(HWND tool_tips_handle, TTTOOLINFOA *tool_info);

        void set_tool_info(HWND tool_tips_handle, TTTOOLINFOW *tool_info);

        void set_tool_rect(HWND tool_tips_handle, TTTOOLINFOA *tool_info);

        void set_tool_rect(HWND tool_tips_handle, TTTOOLINFOW *tool_info);

        int32_t get_delay_time(HWND tool_tips_handle, TTDelayTime delay_time);

        void set_delay_time(HWND tool_tips_handle,
                            TTDelayTime delay_time,
                            int32_t delay_ms);

        void get_margin(HWND tool_tips_handle, RECT *rect);

        void set_margin(HWND tool_tips_handle, RECT *rect);

        int64_t get_max_tip_width(HWND tool_tips_handle);

        int64_t get_max_tip_width(HWND tool_tips_handle, int64_t width);

        COLORREF get_tip_background_color(HWND tool_tips_handle);

        void set_tip_background_color(HWND tool_tips_handle, COLORREF color);

        COLORREF get_text_background_color(HWND tool_tips_handle);

        void set_text_background_color(HWND tool_tips_handle, COLORREF color);

        void get_title(HWND tool_tips_handle, TTGETTITLE *title);

        bool set_title(HWND tool_tips_handle,
                       TTTitleType type,
                       std::string &title,
                       helper::CodePage code_page = helper::curr_code_page());

        bool
        set_title(HWND tool_tips_handle, TTTitleType type, std::wstring &title);

        bool set_title(HWND tool_tips_handle,
                       HICON icon_handle,
                       std::string &title,
                       helper::CodePage code_page = helper::curr_code_page());

        bool set_title(HWND tool_tips_handle,
                       HICON icon_handle,
                       std::wstring &title);

        // std::pair<width, height>
        std::pair<uint32_t, uint32_t> get_bubble_size(HWND tool_tips_handle,
                                                      TTTOOLINFOW *tool_info);

        bool get_curr_tool(HWND tool_tips_handle, TTTOOLINFOA *tool_info);

        bool get_curr_tool(HWND tool_tips_handle, TTTOOLINFOW *tool_info);

        // text_size = strlen(tool_info->lpszText);
        void get_text(HWND tool_tips_handle,
                      int64_t text_size,
                      TTTOOLINFOA *tool_info);

        // text_size = wcslen(tool_info->lpszText) * sizeof(wchar_t);
        void get_text(HWND tool_tips_handle,
                      int64_t text_size,
                      TTTOOLINFOW *tool_info);

        void update_text(HWND tool_tips_handle, TTTOOLINFOA *tool_info);

        void update_text(HWND tool_tips_handle, TTTOOLINFOW *tool_info);

        bool display_rect_to_window_rect(HWND tool_tips_handle, RECT *rect);

        bool window_rect_to_display_rect(HWND tool_tips_handle, RECT *rect);

        bool hit_test(HWND tool_tips_handle, TTHITTESTINFOA *hit_test_info);

        bool hit_test(HWND tool_tips_handle, TTHITTESTINFOW *hit_test_info);

        HWND window_from_point(HWND tool_tips_handle, POINT *point);

        void relay_event(HWND tool_tips_handle, MSG *msg);

        void pop(HWND tool_tips_handle);

        void popup(HWND tool_tips_handle);

        void update(HWND tool_tips_handle);

        void
        set_window_theme(HWND tool_tips_handle,
                         std::string &theme,
                         helper::CodePage code_page = helper::curr_code_page());

        void set_window_theme(HWND tool_tips_handle, std::wstring &theme);

        [[nodiscard]] uint32_t err_code() const;

        [[nodiscard]] std::string err_string() const;

        [[nodiscard]] std::wstring err_wstring() const;
    };
} // namespace YanLib::ui::components
#endif // TOOL_TIPS_H
