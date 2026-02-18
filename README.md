# lje-ffi

A native FFI and memory manipulation module for [LJE](https://github.com/lj-expand/lj-expand). Provides low-level access to process memory, C struct layout parsing, function hooking, disassembly, and foreign function calls from Lua.

You can think of it as a lightweight alternative to things like [Frida](https://frida.re/) or [Cheat Engine's Lua engine](https://wiki.cheatengine.org/index.php?title=Tutorials:Lua:Basics) built directly into LJE for easy use in GMod.
Although, it is not that similar to the similarly named [LuaJIT FFI library](https://luajit.org/ext_ffi.html), which is a different beast entirely, not exactly meant for game hooking/reversing.

## Disclaimer

lje-ffi **inherently** has the potential to be used for malicious purposes, like executing arbitrary code, or bypassing LJE limitations.
This is a powerful tool, and such issues are not the responsibility of the module.

**You must be careful when using this module**, ensure every script you use with LJE is **vetted** and **trusted**. Do not use this module with untrusted scripts, as it can lead to severe security issues.

However, *NO* foreign code can access the FFI module. The FFI module has active protection against this situation, so it is perfectly safe to use FFI while connected to an untrusted server, their Lua cannot interact with the FFI module at all.

## Modules

- **mem** -- Read, write, and protect memory. Includes safe (`try_read_*`) variants that return nil instead of crashing on bad addresses. Also provides pattern scanning, pointer chain dereferencing, and heap enumeration.
- **struct** -- Define C struct/union layouts from a string definition and read/write them directly from memory as Lua tables. Supports nested types, arrays, pointers, padding/offset directives, and attributes like `[[string]]` and `[[unaligned]]`.
- **call** -- Call arbitrary native functions by address using libffi, with support for common calling conventions and type signatures.
- **hook** -- Hook native functions via MinHook. Redirect execution to Lua callbacks and call the original function from within the hook.
- **disasm** -- Disassemble instructions at an address using Capstone. Includes helpers to extract call targets and RIP-relative global references from a function body.
- **vtable** -- Read and manipulate C++ virtual function tables.
- **module** -- Query loaded modules (DLLs) for base addresses and exports.

## Usage

This module is meant to be used in LJE scripts to provide low-level access to the engine, or really anything in the process. FFI unlocks an entirely new level of power and flexibility for LJE scripts.
You definitely need to be somewhat familiar with reverse engineering and low-level programming to use this module effectively, but it can be an invaluable tool for advanced users.

Here's a simple example of unlocking a ConVar to be modifiable by Lua:

```lua
local nameConVar = GetConVar_Internal("name")

local function makeCvarWritable(cvar)
    local flagPtr = ffi.mem.deref(ffi.mem.unwrap_userdata(cvar), {0x00, 0x38, 0x28}) -- obj -> m_pParent -> m_nFlags
    if flagPtr then
        local flags = ffi.mem.try_read_u32(flagPtr) or 0
        lje.con_printf("$green{[netinspect]} Current flags for ConVar '%s': $yellow{0x%X}", cvar:GetName(), flags)
        local newFlags = bit.bor(flags, FCVAR_LUA_CLIENT)
        ffi.mem.try_write_u32(flagPtr, newFlags)
        lje.con_printf("$green{[netinspect]} Updated flags for ConVar '%s': $yellow{0x%X}", cvar:GetName(), newFlags)
    else
        lje.con_printf("$red{[netinspect]} Failed to find flags for ConVar '%s'!", cvar:GetName())
    end
end


makeCvarWritable(nameConVar)
local randomString = ""
for i = 1, 32 do
    randomString = randomString .. string.char(math.random(1, 255))
end
nameConVar:SetString(randomString)
```

It very simply gets the `name` ConVar, finds the pointer to its flags, and sets the `FCVAR_LUA_CLIENT` flag to make it modifiable by Lua. Then it sets a random string as the player's name.

This is just scratching the surface of what you can do with this module. You can hook engine functions, call native functions directly from Lua, read and write complex data structures in memory, and much more.

It is possible to essentially reconstruct or build brand new interfaces to the engine using this module, which can be very powerful for creating advanced scripts or cheats. In these cases, you can worry less about detection, since normal Lua scripts do not even have the capability to do these things in the first place, so anti-cheat systems won't be looking for it. However, you should still be careful to avoid creating instability or crashes.

## Building

```bash
git submodule update --init --recursive
cmake --preset x64-windows-rel
cmake --build --preset x64-windows-rel
```

Output: `build/x64-windows-rel/lje-ffi.dll`

## License

TODO: Add license
