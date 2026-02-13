-- Chaos mode: random WASD + mouse jitter via SendInput
-- Makes your character drunkenly stumble around
-- F11 to stop (auto-stops after 10 seconds)

local ffi = lje.ffi

local user32 = ffi.module.find("user32.dll")
local SendInput        = ffi.module.export(user32, "SendInput")
local GetAsyncKeyState = ffi.module.export(user32, "GetAsyncKeyState")

-- Constants
local INPUT_KEYBOARD       = 1
local INPUT_MOUSE          = 0
local KEYEVENTF_KEYUP      = 0x0002
local KEYEVENTF_SCANCODE   = 0x0008
local MOUSEEVENTF_MOVE     = 0x0001
local INPUT_SIZE           = 40 -- sizeof(INPUT) on x64

local VK_F11 = 0x7A

-- Hardware scan codes (what DirectInput/Raw Input actually reads)
local SCAN_W, SCAN_A, SCAN_S, SCAN_D = 0x11, 0x1E, 0x1F, 0x20
local WASD       = { SCAN_W, SCAN_A, SCAN_S, SCAN_D }
local WASD_NAMES = { "W", "A", "S", "D" }

local random = math.random
local input  = ffi.mem.alloc(INPUT_SIZE)

----------------------------------------------------------------------
-- INPUT struct layout (x64):
--   offset 0:  type      (DWORD)
--   offset 4:  padding
--   offset 8:  union start
--
-- KEYBDINPUT (from offset 8):
--   +0  wVk       (WORD)    -> INPUT+8
--   +2  wScan     (WORD)    -> INPUT+10
--   +4  dwFlags   (DWORD)   -> INPUT+12
--
-- MOUSEINPUT (from offset 8):
--   +0  dx        (LONG)    -> INPUT+8
--   +4  dy        (LONG)    -> INPUT+12
--   +8  mouseData (DWORD)   -> INPUT+16
--  +12  dwFlags   (DWORD)   -> INPUT+20
----------------------------------------------------------------------

local function send_key(scan, up)
    ffi.mem.fill(input, 0, INPUT_SIZE)
    ffi.mem.write_u32(input, INPUT_KEYBOARD)
    ffi.mem.write_u16(input + 10, scan)         -- wScan at offset 10
    local flags = KEYEVENTF_SCANCODE
    if up then flags = flags + KEYEVENTF_KEYUP end
    ffi.mem.write_u32(input + 12, flags)
    ffi.call.invoke(SendInput, "uupi", 1, input, INPUT_SIZE)
end

local function send_mouse(dx, dy)
    ffi.mem.fill(input, 0, INPUT_SIZE)
    ffi.mem.write_u32(input, INPUT_MOUSE)
    ffi.mem.write_i32(input + 8, dx)
    ffi.mem.write_i32(input + 12, dy)
    ffi.mem.write_u32(input + 20, MOUSEEVENTF_MOVE)
    ffi.call.invoke(SendInput, "uupi", 1, input, INPUT_SIZE)
end

local current_key = nil
local tick  = 0
local alive = true
local MAX_TICKS = 600 -- ~10s at 60fps

local function cleanup()
    if not alive then return end
    alive = false
    if current_key then send_key(current_key, true) end
    hook.removepre("ljeutil/render", "sendinput.chaos")
    ffi.mem.free(input)
    print("Chaos stopped!")
end

hook.pre("ljeutil/render", "sendinput.chaos", function()
    if not alive then return end

    -- F11 to bail out
    if ffi.call.invoke(GetAsyncKeyState, "ii", VK_F11) < 0 then
        cleanup()
        return
    end

    tick = tick + 1
    if tick > MAX_TICKS then
        cleanup()
        return
    end

    -- Pick a new random direction every ~20 frames
    if tick % 20 == 0 then
        if current_key then send_key(current_key, true) end
        local idx = random(1, 4)
        current_key = WASD[idx]
        send_key(current_key, false)
        print("Moving: " .. WASD_NAMES[idx])
    end

    -- Jiggle the mouse each frame
    send_mouse(random(-8, 8), random(-3, 3))
end)

print("Chaos mode ON! Press F11 to stop (auto-stops in 10s)")
