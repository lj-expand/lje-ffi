---
id: quickstart
---

# LJE FFI Quickstart

This guide will show you the most common use cases of lje-ffi, and how to get comfortable with it.

Quick notes:
1. Every pointer is a regular Lua number. This is because all Lua numbers support 53 bits of precision, which is more than enough to represent any pointer on a 64-bit system.
2. All functions that take pointers will accept Lua numbers as pointers, and all functions that return pointers will return Lua numbers as pointers.
3. Multi-threading is not necessarily supported, but you could probably get away with it if you know what you're doing. Just be careful when sharing data between threads, and make sure to use proper synchronization mechanisms to avoid

## Binding and Calling Functions

This will be your main use of lje-ffi. There are two modes of calling functions:

- [Bind](/api/call#bind) (Recommended): Binding functions creates a re-usable C closure that is faster to call, and can be used in multiple places. This is the recommended way of calling functions.
- [Invoke](/api/call#invoke) (Legacy): This is a one-off way of calling functions that does not create a C closure. It is slightly slower than binding, and is not recommended for repeated calls.

You specify a function's signature through a simple type string, where each character represents a type. The first character is the return type, and the rest are the parameter types. For example, `uupi` means the function returns an unsigned int, and takes two unsigned ints and an int as parameters.
See the [callback creation page for a comprehensive list of type characters](/api/callback#create).

Here are the C equivalents:
- `ipp` -> `int func(void* param1, void* param2)`
- `uupi` -> `unsigned int func(unsigned int param1, void* param2, int param3)`
- `v` -> `void func()`
- etc.

You need to first know the function's address to call it, in this example, we'll call `MessageBoxA` from `user32.dll`, which has the following signature:
```c
int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
```

In our signature string, this would be `ipssu` (returns an int, takes a pointer, two strings, and an unsigned int). We can bind this function as follows:

```lua
local user32 = ffi.module.find("user32.dll")
local MessageBoxA = ffi.module.bind_export(user32, "MessageBoxA", "ipssu")

MessageBoxA(nil, "Hello, world!", "LJE FFI Quickstart", 0)
```

This will display a message box with the text "Hello, world!" and the caption "LJE FFI Quickstart". You can call `MessageBoxA` as many times as you want, and it will be very fast since we bound it.
Note that any use of `s` automatically converts Lua strings to C strings, so you can just pass Lua strings directly without worrying about memory management.

## Memory

Another very common necessity is memory management. The module exposes several ways to go about this.

### Raw Memory Access

You can choose between two methods of raw memory access:
- Checked (Recommended): This method has guards to prevent a crash if you end up dereferencing an invalid pointer. It returns `nil` if the pointer is invalid, so you can check for that and handle it gracefully. This is the recommended way of accessing memory.
- Unchecked: This method does not have any guards, and will crash if you dereference an invalid pointer. This is not recommended unless you have a specific reason to use it.

See the [memory module docs](/api/mem) for a comprehensive list of memory access functions and their signatures.

### Allocating and Freeing Memory

You can allocate and free memory using `ffi.mem.alloc` and `ffi.mem.free`. These functions work similarly to `malloc` and `free` in C. Just be sure to free any memory you allocate when you're done with it to avoid memory leaks.

```lua
local ptr = ffi.mem.alloc(256) -- allocate 256 bytes of memory
ffi.mem.free(ptr) -- free the allocated memory
```

### Structures

You can also use the powerful [struct module](/api/struct) to define and work with C-like structures in Lua. This allows you to easily read and write structured data in memory, and can be very useful when working with complex data.

```lua
ffi.struct.define([[
struct MyStruct {
  int a;
  float b;
  char c;
};
]])

local my_struct = ffi.mem.alloc(ffi.struct.sizeof("MyStruct"))
ffi.mem.fill(my_struct, 0, ffi.struct.sizeof("MyStruct")) -- zero out the memory

my_struct = ffi.struct.cast(my_struct, "MyStruct") -- cast the pointer to our struct type
my_struct.a = 42
my_struct.b = 3.14
my_struct.c = 65 -- ASCII for 'A'

-- NOTE: Currently array fields in structs aren't supported using cast.
-- This is the alternate method using the raw read/write functions:

ffi.struct.write(my_struct, "MyStruct", {
  a = 42,
  b = 3.14,
  c = 65,
})

local data = ffi.struct.read(my_struct, "MyStruct")
print(data.a) -- 42
print(data.b) -- 3.14
print(string.char(data.c)) -- 'A'
```

## Finding Classes

This is a very common use case when you want to find a Source Engine class. The module exposes a very simple way to do it using [find_instances](/api/vtable#find_instances). This function takes a class name and returns a list of all instances of that class in memory.

```lua
-- Find all `CBaseClientState` instances in memory
local engine = ffi.module.find("engine.dll")
local CBaseClientState = ffi.vtable.find_instances(engine, "CBaseClientState") -- returns first match, see docs for more options

lje.con_printf("$green{Found CBaseClientState at %p}", CBaseClientState)
```

## Using Signatures

lje-ffi automagically masks signatures, so feel free to use them directly without worrying about it.

For most cases, you want to [scan a specific module's code section](/api/module#scan) for a signature like so.

```lua
local client = ffi.module.find("client.dll")
local my_function = ffi.module.scan(client, "48 89 5C 24 78 57 48 83 EC 20 48 8B F9 E8")

-- If the signature is found, `my_function` will be the address of the first match. If it's not found, it will be `nil`.
if my_function then
  lje.con_printf("$green{Found function at address: %p}", my_function)
else
  lje.con_print("$red{Failed to find function with signature}")
end

-- For debugging, LJE FFI will always print out the result of the automasking,
-- see docs for options to disable this if you don't want it.
```

## Detours

Detours are quite complicated. If you need undetectable detours, you need to use the [C detour module](/api/detour) instead of the [Lua detour module](/api/hook).

### C Detours

To make a C detour, you need to write your detour function in C with two required definitions, `original` and `detour`.
`original` is a function pointer that will point to the original function, and `detour` is your detour function that will be called instead of the original function. You can call the original function from your detour using the `original` function pointer.

```c
// detours/openurl.c
// Blocks anything from opening a URL.

#include <stddef.h>
#include <stdio.h>

void (*original)(void* this_ptr, const char* url);
void detour(void* this_ptr, const char* url) {
  original(this_ptr, "https://127.0.0.1"); /* still call it, so it does not create a timing difference */
}
```

Then, in Lua, you want to create a detour object and store it globally to ensure it will not be garbage collected.

```lua
--- Do whatever to find the address
local openURL = ...

openURLDetour = ffi.detour.create(openURL, lje.env.read_script_file("detours/openurl.c"))
```

This will automatically handle creating and enabling the detour for you. You can disable and free the detour when you're done with it like so:

```lua
openURLDetour:remove()
openURLDetour = nil
```

This is important to do in `lje.env.on_cleanup` or when you run again in hotreload to avoid having multiple detours on the same function, which can cause instability.

Additionally, see the docs on the [Detour](/api/detour#Detour) class to see a full list of methods.

### Lua Detours

These are legacy and not recommended, but in case you do not require undetectable detours, you can use the Lua detour module to create detours in Lua. This is much simpler than C detours, but it is also easily detectable by adversarial scripts, so be aware of the risks.

```lua
local target = ... -- Address
local handle = ffi.hook.create(target, "ipi", function(original, this_ptr, param)
  -- Do something
  ffi.call.invoke(original, "ipi", this_ptr, param) -- Call the original function if needed
  return 1337 -- Return value for the original function, if needed
end)

--- Later..

ffi.hook.remove(handle)
```

Additionally, you can use bound closures as well.
```lua
local target = ffi.call.bind(address, "ipi") -- Bind the target function to a closure
local handle = ffi.hook.create_bind(target, function(original, this_ptr, param)
  -- Do something
  original(this_ptr, param) -- Call the original function if needed
  return 1337 -- Return value for the original function, if needed
end)

--- Later..
ffi.hook.remove(handle)
```

## Miscellaneous

There are other miscellaneous features of the module, including:
- [Disassembly](/api/disasm): You can disassemble code at a given address to get a list of instructions. This can be useful for automating reverse engineering tasks.
- [Callbacks](/api/callback): You can create C callbacks that can be passed to C functions. This is useful for things like thread entry points, window procedures, etc.
- [TCC](/api/tcc): You can compile and execute C code at runtime using the Tiny C Compiler. This is a powerful feature that allows you to write general-purpose C code on the fly and execute it without needing to write a full binary module.

Make sure to check out each API reference page for more details and examples on how to use these features!
