-- Flashy Win32 window using lje-ffi
-- Cycling background + random colored pixels
-- NOTE: The message loop blocks the current thread.

local ffi = lje.ffi

-- Resolve function addresses
local user32   = ffi.module.find("user32.dll")
local kernel32 = ffi.module.find("kernel32.dll")
local gdi32    = ffi.module.find("gdi32.dll")

local RegisterClassExA = ffi.module.export(user32, "RegisterClassExA")
local CreateWindowExA  = ffi.module.export(user32, "CreateWindowExA")
local ShowWindow       = ffi.module.export(user32, "ShowWindow")
local GetMessageA      = ffi.module.export(user32, "GetMessageA")
local TranslateMessage = ffi.module.export(user32, "TranslateMessage")
local DispatchMessageA = ffi.module.export(user32, "DispatchMessageA")
local DefWindowProcA   = ffi.module.export(user32, "DefWindowProcA")
local PostQuitMessage  = ffi.module.export(user32, "PostQuitMessage")
local LoadCursorA      = ffi.module.export(user32, "LoadCursorA")
local BeginPaint       = ffi.module.export(user32, "BeginPaint")
local EndPaint         = ffi.module.export(user32, "EndPaint")
local GetClientRect    = ffi.module.export(user32, "GetClientRect")
local FillRect         = ffi.module.export(user32, "FillRect")
local SetTimer         = ffi.module.export(user32, "SetTimer")
local KillTimer        = ffi.module.export(user32, "KillTimer")
local InvalidateRect   = ffi.module.export(user32, "InvalidateRect")
local GetModuleHandleA = ffi.module.export(kernel32, "GetModuleHandleA")

local CreateSolidBrush = ffi.module.export(gdi32, "CreateSolidBrush")
local DeleteObject     = ffi.module.export(gdi32, "DeleteObject")
local SetBkMode        = ffi.module.export(gdi32, "SetBkMode")
local SetTextColor     = ffi.module.export(gdi32, "SetTextColor")
local TextOutA         = ffi.module.export(gdi32, "TextOutA")
local SetPixelV        = ffi.module.export(gdi32, "SetPixelV")

-- Constants
local CS_HREDRAW          = 0x0002
local CS_VREDRAW          = 0x0001
local WS_OVERLAPPEDWINDOW = 0x00CF0000
local WS_VISIBLE          = 0x10000000
local SW_SHOW             = 5
local COLOR_WINDOW        = 5
local IDC_ARROW           = 32512
local WM_DESTROY          = 0x0002
local WM_PAINT            = 0x000F
local WM_TIMER            = 0x0113
local TRANSPARENT         = 1
local TIMER_ID            = 1

local sin, floor, random = math.sin, math.floor, math.random

-- RGB -> COLORREF (0x00BBGGRR)
local function rgb(r, g, b)
    return r + g * 256 + b * 65536
end

-- Smooth rainbow from a phase value
local function rainbow(t)
    local r = floor(sin(t)         * 127 + 128)
    local g = floor(sin(t + 2.094) * 127 + 128)
    local b = floor(sin(t + 4.189) * 127 + 128)
    return rgb(r, g, b)
end

-- Handles
local hInstance = ffi.call.invoke(GetModuleHandleA, "pp", 0)
local hCursor   = ffi.call.invoke(LoadCursorA, "ppp", 0, IDC_ARROW)

-- Reusable buffers
local ps   = ffi.mem.alloc(72)  -- PAINTSTRUCT (72 bytes on x64)
local rect = ffi.mem.alloc(16)  -- RECT (4x int32)

local frame = 0
local greeting = "Hello from LJE-FFI!"

-- WndProc callback (signature: LRESULT(HWND, UINT, WPARAM, LPARAM))
local wndproc_cb, wndproc_addr = ffi.callback.create("ppupp", function(hwnd, msg, wp, lp)
    if msg == WM_PAINT then
        local hdc = ffi.call.invoke(BeginPaint, "ppp", hwnd, ps)
        frame = frame + 1
        local t = frame * 0.05

        -- Get client area dimensions
        ffi.call.invoke(GetClientRect, "ipp", hwnd, rect)
        local cw = ffi.mem.read_i32(rect + 8)   -- right
        local ch = ffi.mem.read_i32(rect + 12)   -- bottom

        -- Fill background with cycling color
        local bg = CreateSolidBrush
        local bg_brush = ffi.call.invoke(bg, "pu", rainbow(t))
        ffi.call.invoke(FillRect, "ippp", hdc, rect, bg_brush)
        ffi.call.invoke(DeleteObject, "ip", bg_brush)

        -- Scatter random colored pixels
        for i = 1, 500 do
            local px = random(0, cw)
            local py = random(0, ch)
            ffi.call.invoke(SetPixelV, "ipiiu", hdc, px, py,
                rgb(random(0, 255), random(0, 255), random(0, 255)))
        end

        -- Draw text with transparent background and white color
        ffi.call.invoke(SetBkMode, "ipi", hdc, TRANSPARENT)
        ffi.call.invoke(SetTextColor, "upu", hdc, rgb(255, 255, 255))
        ffi.call.invoke(TextOutA, "ipiisi", hdc, 20, 20, greeting, #greeting)

        ffi.call.invoke(EndPaint, "ipp", hwnd, ps)
        return 0
    elseif msg == WM_TIMER then
        -- Timer tick -> repaint
        ffi.call.invoke(InvalidateRect, "ippi", hwnd, 0, 0)
        return 0
    elseif msg == WM_DESTROY then
        ffi.call.invoke(KillTimer, "ipp", hwnd, TIMER_ID)
        ffi.call.invoke(PostQuitMessage, "vi", 0)
        return 0
    end
    return ffi.call.invoke(DefWindowProcA, "ppupp", hwnd, msg, wp, lp)
end)

-- Define and fill WNDCLASSEXA
ffi.struct.define([[
    struct WNDCLASSEXA {
        uint32_t cbSize;
        uint32_t style;
        void*    lpfnWndProc;
        int      cbClsExtra;
        int      cbWndExtra;
        void*    hInstance;
        void*    hIcon;
        void*    hCursor;
        void*    hbrBackground;
        char*    lpszMenuName;
        char*    lpszClassName;
        void*    hIconSm;
    }
]])

local class_name = ffi.mem.alloc(32)
ffi.mem.write_string(class_name, "LJE_Window")

local wc_size = ffi.struct.sizeof("WNDCLASSEXA")
local wc = ffi.mem.alloc(wc_size)
ffi.mem.fill(wc, 0, wc_size)
ffi.struct.write(wc, "WNDCLASSEXA", {
    cbSize        = wc_size,
    style         = CS_HREDRAW + CS_VREDRAW,
    lpfnWndProc   = wndproc_addr,
    hInstance     = hInstance,
    hCursor       = hCursor,
    hbrBackground = COLOR_WINDOW + 1,
    lpszClassName = class_name,
})

local atom = ffi.call.invoke(RegisterClassExA, "up", wc)
assert(atom ~= 0, "RegisterClassExA failed")

-- Create and show window
local hwnd = ffi.call.invoke(CreateWindowExA, "pussuiiiipppp",
    0, "LJE_Window", "Hello from LJE-FFI!",
    WS_OVERLAPPEDWINDOW + WS_VISIBLE,
    100, 100, 800, 600,
    0, 0, hInstance, 0)
assert(hwnd ~= 0, "CreateWindowExA failed")

ffi.call.invoke(ShowWindow, "ipi", hwnd, SW_SHOW)

-- Start a 30ms timer to drive repaints (~33 FPS)
ffi.call.invoke(SetTimer, "pppup", hwnd, TIMER_ID, 30, 0)

-- Message loop (48 bytes = sizeof(MSG) on x64)
local msg_buf = ffi.mem.alloc(48)
while ffi.call.invoke(GetMessageA, "ippuu", msg_buf, 0, 0, 0) > 0 do
    ffi.call.invoke(TranslateMessage, "ip", msg_buf)
    ffi.call.invoke(DispatchMessageA, "ip", msg_buf)
end

-- Cleanup
ffi.mem.free(msg_buf)
ffi.mem.free(ps)
ffi.mem.free(rect)
ffi.mem.free(wc)
ffi.mem.free(class_name)
ffi.callback.remove(wndproc_cb)
print("Window closed!")
