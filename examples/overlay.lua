-- Transparent overlay that tracks the host window's client area
-- Non-blocking: pumps messages each frame via hook.pre
-- F12 to close

local ffi = lje.ffi

-- Resolve function addresses
local user32   = ffi.module.find("user32.dll")
local kernel32 = ffi.module.find("kernel32.dll")
local gdi32    = ffi.module.find("gdi32.dll")

local RegisterClassExA           = ffi.module.export(user32, "RegisterClassExA")
local CreateWindowExA            = ffi.module.export(user32, "CreateWindowExA")
local DestroyWindow              = ffi.module.export(user32, "DestroyWindow")
local ShowWindow                 = ffi.module.export(user32, "ShowWindow")
local PeekMessageA               = ffi.module.export(user32, "PeekMessageA")
local TranslateMessage           = ffi.module.export(user32, "TranslateMessage")
local DispatchMessageA           = ffi.module.export(user32, "DispatchMessageA")
local DefWindowProcA             = ffi.module.export(user32, "DefWindowProcA")
local PostQuitMessage            = ffi.module.export(user32, "PostQuitMessage")
local SetLayeredWindowAttributes = ffi.module.export(user32, "SetLayeredWindowAttributes")
local InvalidateRect             = ffi.module.export(user32, "InvalidateRect")
local BeginPaint                 = ffi.module.export(user32, "BeginPaint")
local EndPaint                   = ffi.module.export(user32, "EndPaint")
local RegisterHotKey             = ffi.module.export(user32, "RegisterHotKey")
local UnregisterHotKey           = ffi.module.export(user32, "UnregisterHotKey")
local GetClientRect              = ffi.module.export(user32, "GetClientRect")
local FillRect                   = ffi.module.export(user32, "FillRect")
local ClientToScreen             = ffi.module.export(user32, "ClientToScreen")
local MoveWindow                 = ffi.module.export(user32, "MoveWindow")
local IsWindow                   = ffi.module.export(user32, "IsWindow")
local IsWindowVisible            = ffi.module.export(user32, "IsWindowVisible")
local EnumWindows                = ffi.module.export(user32, "EnumWindows")
local GetWindowThreadProcessId   = ffi.module.export(user32, "GetWindowThreadProcessId")
local GetModuleHandleA           = ffi.module.export(kernel32, "GetModuleHandleA")
local GetCurrentProcessId        = ffi.module.export(kernel32, "GetCurrentProcessId")

local CreateSolidBrush = ffi.module.export(gdi32, "CreateSolidBrush")
local CreatePen        = ffi.module.export(gdi32, "CreatePen")
local SelectObject     = ffi.module.export(gdi32, "SelectObject")
local DeleteObject     = ffi.module.export(gdi32, "DeleteObject")
local MoveToEx         = ffi.module.export(gdi32, "MoveToEx")
local LineTo           = ffi.module.export(gdi32, "LineTo")
local SetBkMode        = ffi.module.export(gdi32, "SetBkMode")
local SetTextColor     = ffi.module.export(gdi32, "SetTextColor")
local TextOutA         = ffi.module.export(gdi32, "TextOutA")

-- Constants
local WS_POPUP          = 0x80000000
local WS_VISIBLE        = 0x10000000
local WS_EX_LAYERED     = 0x00080000
local WS_EX_TOPMOST     = 0x00000008
local WS_EX_TRANSPARENT = 0x00000020
local WS_EX_TOOLWINDOW  = 0x00000080
local LWA_COLORKEY      = 1
local PS_SOLID          = 0
local SW_SHOW           = 5
local PM_REMOVE         = 0x0001
local WM_PAINT          = 0x000F
local WM_DESTROY        = 0x0002
local WM_QUIT           = 0x0012
local WM_ERASEBKGND     = 0x0014
local WM_HOTKEY         = 0x0312
local VK_F12            = 0x7B

local sin, floor = math.sin, math.floor

local function rgb(r, g, b)
    return r + g * 256 + b * 65536
end

local MAGENTA = rgb(255, 0, 255)

----------------------------------------------------------------------
-- Find the host window (first visible window in our process)
----------------------------------------------------------------------
local our_pid = ffi.call.invoke(GetCurrentProcessId, "u")
local pid_buf = ffi.mem.alloc(4)
local target  = 0

local enum_cb, enum_addr = ffi.callback.create("ipp", function(hwnd, _)
    ffi.call.invoke(GetWindowThreadProcessId, "upp", hwnd, pid_buf)
    if ffi.mem.read_u32(pid_buf) == our_pid
       and ffi.call.invoke(IsWindowVisible, "ip", hwnd) ~= 0 then
        target = hwnd
        return 0
    end
    return 1
end)

ffi.call.invoke(EnumWindows, "ipp", enum_addr, 0)
ffi.callback.remove(enum_cb)
ffi.mem.free(pid_buf)
assert(target ~= 0, "Could not find host window")

----------------------------------------------------------------------
-- Read target's client area in screen coordinates
----------------------------------------------------------------------
local rect  = ffi.mem.alloc(16)
local point = ffi.mem.alloc(8)

local function read_target_rect()
    ffi.call.invoke(GetClientRect, "ipp", target, rect)
    local w = ffi.mem.read_i32(rect + 8)
    local h = ffi.mem.read_i32(rect + 12)
    ffi.mem.write_i32(point, 0)
    ffi.mem.write_i32(point + 4, 0)
    ffi.call.invoke(ClientToScreen, "ipp", target, point)
    return ffi.mem.read_i32(point), ffi.mem.read_i32(point + 4), w, h
end

local ox, oy, cw, ch = read_target_rect()

----------------------------------------------------------------------
-- Overlay
----------------------------------------------------------------------
local hInstance = ffi.call.invoke(GetModuleHandleA, "pp", 0)
local bg_brush  = ffi.call.invoke(CreateSolidBrush, "pu", MAGENTA)

local ps      = ffi.mem.alloc(72)
local msg_buf = ffi.mem.alloc(48)
local frame   = 0
local alive   = true
local overlay = 0 -- filled after CreateWindowExA

local function cleanup()
    if not alive then return end
    alive = false
    hook.removepre("ljeutil/render", "window.msg")
    ffi.mem.free(msg_buf)
    ffi.mem.free(ps)
    ffi.mem.free(rect)
    ffi.mem.free(point)
    ffi.mem.free(wc)
    ffi.mem.free(class_name)
    ffi.call.invoke(DeleteObject, "ip", bg_brush)
    ffi.callback.remove(wndproc_cb)
    print("Overlay closed!")
end

-- WndProc — only handles paint, hotkey, destroy (no timer needed)
wndproc_cb, wndproc_addr = ffi.callback.create("ppupp", function(hwnd, msg, wp, lp)
    if msg == WM_ERASEBKGND then
        return 1 -- skip system erase, we paint the background ourselves

    elseif msg == WM_PAINT then
        local hdc = ffi.call.invoke(BeginPaint, "ppp", hwnd, ps)
        frame = frame + 1
        local t = frame * 0.03

        -- Clear to magenta (transparent) in the same pass as drawing
        ffi.call.invoke(GetClientRect, "ipp", hwnd, rect)
        ffi.call.invoke(FillRect, "ippp", hdc, rect, bg_brush)

        local mx = floor(cw / 2)
        local my = floor(ch / 2)

        -- Pulsing green crosshair with gap
        local g = floor(sin(t) * 55 + 200)
        local pen = ffi.call.invoke(CreatePen, "piiu", PS_SOLID, 2, rgb(0, g, 0))
        local old = ffi.call.invoke(SelectObject, "ppp", hdc, pen)

        ffi.call.invoke(MoveToEx, "ipiip", hdc, mx - 20, my, 0)
        ffi.call.invoke(LineTo,   "ipii",  hdc, mx - 4,  my)
        ffi.call.invoke(MoveToEx, "ipiip", hdc, mx + 4,  my, 0)
        ffi.call.invoke(LineTo,   "ipii",  hdc, mx + 20, my)
        ffi.call.invoke(MoveToEx, "ipiip", hdc, mx, my - 20, 0)
        ffi.call.invoke(LineTo,   "ipii",  hdc, mx, my - 4)
        ffi.call.invoke(MoveToEx, "ipiip", hdc, mx, my + 4,  0)
        ffi.call.invoke(LineTo,   "ipii",  hdc, mx, my + 20)

        ffi.call.invoke(SelectObject, "ppp", hdc, old)
        ffi.call.invoke(DeleteObject, "ip", pen)

        ffi.call.invoke(SetBkMode,    "ipi", hdc, 1)
        ffi.call.invoke(SetTextColor, "upu", hdc, rgb(0, 255, 0))
        local text = "LJE-FFI Overlay | F12 to close | frame " .. frame
        ffi.call.invoke(TextOutA, "ipiisi", hdc, 10, 10, text, #text)

        ffi.call.invoke(EndPaint, "ipp", hwnd, ps)
        return 0

    elseif msg == WM_HOTKEY then
        ffi.call.invoke(DestroyWindow, "ip", hwnd)
        return 0

    elseif msg == WM_DESTROY then
        ffi.call.invoke(UnregisterHotKey, "ipi", hwnd, 1)
        ffi.call.invoke(PostQuitMessage, "vi", 0)
        return 0
    end
    return ffi.call.invoke(DefWindowProcA, "ppupp", hwnd, msg, wp, lp)
end)

-- Window class
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

class_name = ffi.mem.alloc(32)
ffi.mem.write_string(class_name, "LJE_Overlay")

local wc_size = ffi.struct.sizeof("WNDCLASSEXA")
wc = ffi.mem.alloc(wc_size)
ffi.mem.fill(wc, 0, wc_size)
ffi.struct.write(wc, "WNDCLASSEXA", {
    cbSize        = wc_size,
    lpfnWndProc   = wndproc_addr,
    hInstance     = hInstance,
    hbrBackground = bg_brush,
    lpszClassName = class_name,
})

local atom = ffi.call.invoke(RegisterClassExA, "up", wc)
assert(atom ~= 0, "RegisterClassExA failed")

local ex = WS_EX_LAYERED + WS_EX_TOPMOST + WS_EX_TRANSPARENT + WS_EX_TOOLWINDOW
overlay = ffi.call.invoke(CreateWindowExA, "pussuiiiipppp",
    ex, "LJE_Overlay", "",
    WS_POPUP + WS_VISIBLE,
    ox, oy, cw, ch,
    0, 0, hInstance, 0)
assert(overlay ~= 0, "CreateWindowExA failed")

ffi.call.invoke(SetLayeredWindowAttributes, "ipuiu", overlay, MAGENTA, 0, LWA_COLORKEY)
ffi.call.invoke(RegisterHotKey, "ipiuu", overlay, 1, 0, VK_F12)
ffi.call.invoke(ShowWindow, "ipi", overlay, SW_SHOW)

----------------------------------------------------------------------
-- Per-frame message pump (non-blocking)
----------------------------------------------------------------------
hook.pre("ljeutil/render", "window.msg", function()
    if not alive then return end

    -- Close if host window is gone
    if ffi.call.invoke(IsWindow, "ip", target) == 0 then
        ffi.call.invoke(DestroyWindow, "ip", overlay)
    end

    -- Track host window position / size
    local nx, ny, nw, nh = read_target_rect()
    if nx ~= ox or ny ~= oy or nw ~= cw or nh ~= ch then
        ox, oy, cw, ch = nx, ny, nw, nh
        ffi.call.invoke(MoveWindow, "ipiiiii", overlay, ox, oy, cw, ch, 1)
    end

    -- Request repaint
    ffi.call.invoke(InvalidateRect, "ippi", overlay, 0, 0)

    -- Drain pending messages
    while ffi.call.invoke(PeekMessageA, "ippuuu", msg_buf, 0, 0, 0, PM_REMOVE) ~= 0 do
        if ffi.mem.read_u32(msg_buf + 8) == WM_QUIT then
            cleanup()
            return
        end
        ffi.call.invoke(TranslateMessage, "ip", msg_buf)
        ffi.call.invoke(DispatchMessageA, "ip", msg_buf)
    end
end)
