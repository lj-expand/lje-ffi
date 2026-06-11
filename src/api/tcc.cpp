#include "tcc.hpp"
#include "../util/call-auth.hpp"
#include "../globals.hpp"

#include <libtcc.h> // TCCState, TCC_OUTPUT_MEMORY, TCC_RELOCATE_AUTO (types/consts only)
#include <miniz.h>

#include <cstdint>
#include <cstring>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace api::tcc {

// Must match the resource id emitted by src/tcc_bundle.rc.in
#define IDR_TCC_BUNDLE 101

// We have to dynamically load libtcc since it's bundled.
struct LibTcc {
    HMODULE module = nullptr;
    TCCState* (*tcc_new)(void) = nullptr;
    void (*tcc_delete)(TCCState*) = nullptr;
    void (*tcc_set_lib_path)(TCCState*, const char*) = nullptr;
    void (*tcc_set_error_func)(TCCState*, void*, void (*)(void*, const char*)) = nullptr;
    int (*tcc_add_include_path)(TCCState*, const char*) = nullptr;
    int (*tcc_add_sysinclude_path)(TCCState*, const char*) = nullptr;
    int (*tcc_set_output_type)(TCCState*, int) = nullptr;
    int (*tcc_compile_string)(TCCState*, const char*) = nullptr;
    int (*tcc_add_symbol)(TCCState*, const char*, const void*) = nullptr;
    int (*tcc_relocate)(TCCState*, void*) = nullptr;
    void* (*tcc_get_symbol)(TCCState*, const char*) = nullptr;
};

static LibTcc T;
static bool s_runtime_ready = false;
static std::string s_last_error;
static std::string s_lib_path_acp;
static std::string s_include_path_acp;

static int s_metatable_ref = LUA_NOREF;

// The main Lua state, exposed to compiled code as the global `L` so that JIT'd
// functions which don't otherwise receive a state can still call into Lua.
static lua_State* s_main_state = nullptr;

struct Program {
    TCCState* state;
    bool destroyed;
};

// Collects libtcc diagnostics so we can hand them back to Lua on failure.
struct ErrorSink {
    std::string text;
};

static void on_tcc_error(void* opaque, const char* msg) {
    auto* sink = static_cast<ErrorSink*>(opaque);
    sink->text += msg;
    sink->text += '\n';
}

// Helper includes/defines for writing lua stackcode.
static const char* PRELUDE = R"PRELUDE(
#include <lje_sdk.h>

extern LjeApi* lje_get_api(void);
extern lua_State* lje_get_state(void);

/* tcc's PE backend can't resolve host *data* symbols through tcc_add_symbol,
   but functions resolve fine - so g_api and the main Lua state are reached via
   accessor functions. g_L is the ambient main state; it is deliberately NOT
   named `L`, so your own functions stay free to take a `lua_State* L` param. */
#define g_api (lje_get_api())
#define g_L   (lje_get_state())

#define lua_pushstring(...)        g_api->lua->pushstring(__VA_ARGS__)
#define lua_tolstring(...)         g_api->lua->tolstring(__VA_ARGS__)
#define lua_pushnumber(...)        g_api->lua->pushnumber(__VA_ARGS__)
#define lua_tonumber(...)          g_api->lua->tonumber(__VA_ARGS__)
#define lua_pushinteger(...)       g_api->lua->pushinteger(__VA_ARGS__)
#define lua_tointeger(...)         g_api->lua->tointeger(__VA_ARGS__)
#define lua_pushlightuserdata(...) g_api->lua->pushlightuserdata(__VA_ARGS__)
#define lua_tolightuserdata(...)   g_api->lua->tolightuserdata(__VA_ARGS__)
#define lua_pushnil(...)           g_api->lua->pushnil(__VA_ARGS__)
#define lua_pushcclosure(...)      g_api->lua->pushcclosure(__VA_ARGS__)
#define lua_gettop(...)            g_api->lua->gettop(__VA_ARGS__)
#define lua_settop(...)            g_api->lua->settop(__VA_ARGS__)
#define lua_call(...)              g_api->lua->call(__VA_ARGS__)
#define lua_pcall(...)             g_api->lua->pcall(__VA_ARGS__)
#define lua_getfield(...)          g_api->lua->getfield(__VA_ARGS__)
#define lua_setfield(...)          g_api->lua->setfield(__VA_ARGS__)
#define lua_pushboolean(...)       g_api->lua->pushboolean(__VA_ARGS__)
#define lua_toboolean(...)         g_api->lua->toboolean(__VA_ARGS__)
#define lua_ref(...)               g_api->lua->ref(__VA_ARGS__)
#define lua_unref(...)             g_api->lua->unref(__VA_ARGS__)
#define lua_rawgeti(...)           g_api->lua->rawgeti(__VA_ARGS__)
#define lua_rawseti(...)           g_api->lua->rawseti(__VA_ARGS__)
#define lua_pushvalue(...)         g_api->lua->pushvalue(__VA_ARGS__)
#define lua_createtable(...)       g_api->lua->createtable(__VA_ARGS__)
#define lua_isnil(...)             g_api->lua->isnil(__VA_ARGS__)
#define lua_type(...)              g_api->lua->type(__VA_ARGS__)
#define lua_typename(...)          g_api->lua->typename_(__VA_ARGS__)
#define lua_objlen(...)            g_api->lua->objlen(__VA_ARGS__)
#define lua_pop(...)               g_api->lua->pop(__VA_ARGS__)
#define lua_pushljeenv(...)        g_api->lua->pushljeenv(__VA_ARGS__)
#define lua_newuserdata(...)       g_api->lua->newuserdata(__VA_ARGS__)
#define lua_touserdata(...)        g_api->lua->touserdata(__VA_ARGS__)
#define lua_setmetatable(...)      g_api->lua->setmetatable(__VA_ARGS__)
#define lua_getupvalue(...)        g_api->lua->getupvalue(__VA_ARGS__)
#define lua_mark_special(...)      g_api->lua->mark_special(__VA_ARGS__)
#define lua_pushlstring(...)       g_api->lua->pushlstring(__VA_ARGS__)
#define lua_tocfunction(...)       g_api->lua->tocfunction(__VA_ARGS__)
#define lua_tostring(L, i)         g_api->lua->tolstring((L), (i), NULL)
)PRELUDE";

// Incredibly annoying but since we cannot trust GMod's directory, and since we cannot bundle more than a few things before
// people become unable to install it, we zip it up during CMake's configure then unzip it here lazily.
static HMODULE self_module() {
    HMODULE h = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&self_module), &h);
    return h;
}

static std::wstring utf8_to_wide(const char* s) {
    if (!s || !*s) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
    return w;
}

static std::string wide_to_acp(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Create every directory along `path` (which is a directory path).
static void create_directories(const std::wstring& path) {
    for (size_t i = 1; i < path.size(); ++i) {
        if (path[i] == L'\\' || path[i] == L'/') {
            std::wstring sub = path.substr(0, i);
            if (!(sub.size() == 2 && sub[1] == L':')) {
                CreateDirectoryW(sub.c_str(), nullptr);
            }
        }
    }
    CreateDirectoryW(path.c_str(), nullptr);
}

static bool write_whole_file(const std::wstring& path, const void* data, size_t size) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    const auto* p = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        DWORD chunk = remaining > 0x10000000 ? 0x10000000 : static_cast<DWORD>(remaining);
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr) || written != chunk) {
            ok = false;
            break;
        }
        p += written;
        remaining -= written;
    }
    CloseHandle(h);
    return ok;
}

// Unpack embedded RCDATA zip to the cache folder.
static bool extract_bundle(const std::wstring& cache) {
    HMODULE self = self_module();
    // RT_RCDATA expands to the ANSI (LPSTR) form when UNICODE isn't defined;
    // it's an integer atom, so cast it to the wide pointer type for *W.
    HRSRC res = FindResourceW(self, MAKEINTRESOURCEW(IDR_TCC_BUNDLE),
                              reinterpret_cast<LPCWSTR>(RT_RCDATA));
    if (!res) {
        s_last_error = "tcc: embedded runtime bundle resource not found";
        return false;
    }
    HGLOBAL glob = LoadResource(self, res);
    void* data = glob ? LockResource(glob) : nullptr;
    DWORD size = SizeofResource(self, res);
    if (!data || size == 0) {
        s_last_error = "tcc: failed to lock embedded runtime bundle";
        return false;
    }

    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, data, size, 0)) {
        s_last_error = "tcc: failed to open embedded runtime bundle";
        return false;
    }

    create_directories(cache);

    bool ok = true;
    mz_uint count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < count && ok; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) continue;

        const char* name = st.m_filename;
        if (name[0] == '.' && (name[1] == '/' || name[1] == '\\')) name += 2;
        if (name[0] == '\0') continue;

        std::wstring rel = utf8_to_wide(name);
        for (auto& c : rel) {
            if (c == L'/') c = L'\\';
        }

        std::wstring dest = cache + L"\\" + rel;

        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            create_directories(dest);
            continue;
        }

        size_t parent = dest.find_last_of(L'\\');
        if (parent != std::wstring::npos) {
            create_directories(dest.substr(0, parent));
        }

        size_t out_size = 0;
        void* file_data = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if (!file_data) {
            s_last_error = "tcc: failed to extract a file from the runtime bundle";
            ok = false;
            break;
        }
        if (!write_whole_file(dest, file_data, out_size)) {
            s_last_error = "tcc: failed to write an extracted runtime file";
            ok = false;
        }
        mz_free(file_data);
    }

    mz_zip_reader_end(&zip);
    return ok;
}

// Pulls in libtcc from the extracted bundle
static bool load_libtcc(const std::wstring& cache) {
    std::wstring dll = cache + L"\\libtcc.dll";
    T.module = LoadLibraryW(dll.c_str());
    if (!T.module) {
        s_last_error = "tcc: failed to load libtcc.dll from cache";
        return false;
    }

#define LOAD_PROC(field)                                                       \
    T.field = reinterpret_cast<decltype(T.field)>(GetProcAddress(T.module, #field)); \
    if (!T.field) {                                                            \
        s_last_error = "tcc: libtcc.dll is missing export " #field;            \
        return false;                                                          \
    }

    LOAD_PROC(tcc_new)
    LOAD_PROC(tcc_delete)
    LOAD_PROC(tcc_set_lib_path)
    LOAD_PROC(tcc_set_error_func)
    LOAD_PROC(tcc_add_include_path)
    LOAD_PROC(tcc_add_sysinclude_path)
    LOAD_PROC(tcc_set_output_type)
    LOAD_PROC(tcc_compile_string)
    LOAD_PROC(tcc_add_symbol)
    LOAD_PROC(tcc_relocate)
    LOAD_PROC(tcc_get_symbol)
#undef LOAD_PROC

    return true;
}

// TCC resolves printf/puts/etc. against the legacy msvcrt.dll it loads itself,
// which keeps its *own* stdout/stderr - separate from the host module's UCRT
// streams that the "[LJE] ..." messages travel through. Freshly loaded, that
// msvcrt's stdout is not attached to the live console, so anything compiled
// code prints is written into a dead stream and silently dropped (the call to
// printf really happens - the bytes just have nowhere to land).
//
// We fix this with a tiny helper compiled by TCC itself, so it links against
// the exact same msvcrt instance user code uses (no fragile sizeof(FILE) /
// _iob offset guessing from the host side). It binds those streams to the
// current console and turns buffering off. Best-effort: if it fails, printf
// simply stays quiet as before.
static void wire_tcc_stdio() {
    static const char* FIXUP = R"FIX(
#include <stdio.h>
int AllocConsole(void);
void __lje_wire_stdio(void) {
    AllocConsole();                   /* no-op if a console already exists */
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered: printf shows immediately */
    setvbuf(stderr, NULL, _IONBF, 0);
}
)FIX";

    TCCState* s = T.tcc_new();
    if (!s) return;

    T.tcc_set_lib_path(s, s_lib_path_acp.c_str());
    T.tcc_add_sysinclude_path(s, s_include_path_acp.c_str());
    T.tcc_add_include_path(s, s_include_path_acp.c_str());
    T.tcc_set_output_type(s, TCC_OUTPUT_MEMORY);

    if (T.tcc_compile_string(s, FIXUP) >= 0 &&
        T.tcc_relocate(s, TCC_RELOCATE_AUTO) >= 0) {
        auto fn = reinterpret_cast<void (*)(void)>(
            T.tcc_get_symbol(s, "__lje_wire_stdio"));
        if (fn) fn();
    }

    // The helper only mutated msvcrt's global streams, so freeing its code now
    // is safe - the reopened stdout/stderr persist in msvcrt itself.
    T.tcc_delete(s);
}

static bool ensure_runtime() {
    if (s_runtime_ready) return true;

    wchar_t profile[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        s_last_error = "tcc: could not resolve %USERPROFILE%";
        return false;
    }

    std::wstring cache = std::wstring(profile) + L"\\.lje\\cache\\ffi-tcc\\" +
                         utf8_to_wide(TCC_BUNDLE_VERSION);
    std::wstring marker = cache + L"\\.ready";

    if (GetFileAttributesW(marker.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (!extract_bundle(cache)) return false;
        // Marker is written last so a partial extraction is retried next time.
        write_whole_file(marker, "", 0);
    }

    if (!load_libtcc(cache)) return false;

    s_lib_path_acp = wide_to_acp(cache);
    s_include_path_acp = wide_to_acp(cache + L"\\include");

    // Bind msvcrt's stdout/stderr to the console so compiled-code printf is
    // actually visible. Needs the lib/include paths set above.
    wire_tcc_stdio();

    s_runtime_ready = true;
    return true;
}

// Accessors exposed to compiled code (see PRELUDE). Compiled code reaches the
// host through these because tcc's PE backend resolves added *functions* but
// not added *data* symbols.
static LjeApi* lje_get_api() { return g_api; }
static lua_State* lje_get_state() { return s_main_state; }

// ---------------------------------------------------------------------------
// Internal compile pipeline (shared with the detour module via tcc.hpp).
// ---------------------------------------------------------------------------
namespace internal {

bool ensure_runtime(std::string& error) {
    if (api::tcc::ensure_runtime()) return true;
    error = s_last_error;
    return false;
}

TCCState* compile(lua_State* L, const char* source, bool use_prelude, std::string& error) {
    s_main_state = L;

    if (!api::tcc::ensure_runtime()) {
        error = s_last_error;
        return nullptr;
    }

    ErrorSink sink;

    TCCState* s = T.tcc_new();
    if (!s) {
        error = "tcc: tcc_new() failed";
        return nullptr;
    }

    T.tcc_set_error_func(s, &sink, on_tcc_error);
    T.tcc_set_lib_path(s, s_lib_path_acp.c_str());
    T.tcc_add_sysinclude_path(s, s_include_path_acp.c_str());
    T.tcc_add_include_path(s, s_include_path_acp.c_str());
    T.tcc_set_output_type(s, TCC_OUTPUT_MEMORY);

    std::string full;
    if (use_prelude) {
        full = PRELUDE;
        full += "\n#line 1 \"tcc\"\n";
    }
    full += source;

    if (T.tcc_compile_string(s, full.c_str()) < 0) {
        error = sink.text.empty() ? "tcc: compilation failed" : sink.text;
        T.tcc_delete(s);
        return nullptr;
    }

    // Resolve the accessor functions the prelude declares. Must happen before
    // relocation. (Data symbols don't resolve on tcc's PE backend; functions do.)
    T.tcc_add_symbol(s, "lje_get_api", reinterpret_cast<const void*>(&lje_get_api));
    T.tcc_add_symbol(s, "lje_get_state", reinterpret_cast<const void*>(&lje_get_state));

    if (T.tcc_relocate(s, TCC_RELOCATE_AUTO) < 0) {
        error = sink.text.empty() ? "tcc: relocation failed" : sink.text;
        T.tcc_delete(s);
        return nullptr;
    }

    return s;
}

void* symbol(TCCState* state, const char* name) {
    if (!state || !T.tcc_get_symbol) return nullptr;
    return T.tcc_get_symbol(state, name);
}

void destroy(TCCState* state) {
    if (state && T.tcc_delete) T.tcc_delete(state);
}

} // namespace internal

// Lua API is given as simple Program objects where it's essentially
// possible for Lua to communicate with C just via static variables.
//
// Point is to allow power users to accelerate certain parts if they so need to,
// or express something cleaner with C. Lua can then use the rest of the FFI library
// on the pointers/functions.

static Program* get_program(lua_State* L, int idx) {
    auto lua = g_api->lua;
    auto** ud = static_cast<Program**>(lua->touserdata(L, idx));
    if (!ud || !*ud || (*ud)->destroyed) {
        return nullptr;
    }
    return *ud;
}

static void cleanup_program(Program* prog) {
    if (!prog || prog->destroyed) return;
    prog->destroyed = true;
    internal::destroy(prog->state); // frees the compiled code as well
    prog->state = nullptr;
}

// __gc metamethod for program userdata
static int gc(lua_State* L) {
    auto lua = g_api->lua;
    auto** ud = static_cast<Program**>(lua->touserdata(L, 1));
    if (ud && *ud) {
        cleanup_program(*ud);
        delete *ud;
        *ud = nullptr;
    }
    return 0;
}

// program:get(name) -> address (number) or nil
// Returns the address of any external-linkage symbol (function or global).
// `static` symbols have internal linkage and are NOT visible here.
static int method_get(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);

    auto* prog = get_program(L, 1);
    if (!prog) {
        lua->pushnil(L);
        return 1;
    }

    const char* name = lua->tolstring(L, 2, nullptr);
    if (!name || !name[0]) {
        lua->pushnil(L);
        return 1;
    }

    void* sym = internal::symbol(prog->state, name);
    if (!sym) {
        lua->pushnil(L);
        return 1;
    }

    lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(sym)));
    return 1;
}

static void push_program_userdata(lua_State* L, Program* prog) {
    auto lua = g_api->lua;
    auto** ud = static_cast<Program**>(lua->newuserdata(L, sizeof(Program*)));
    *ud = prog;
    lua->rawgeti(L, LUA_REGISTRYINDEX, s_metatable_ref);
    lua->setmetatable(L, -2);
}

// tcc.compile(source: string, opts?: table) -> program | nil, error
//   opts.prelude = false  -> skip the injected LJE/Lua prelude
static int compile(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);

    const char* src = lua->tolstring(L, 1, nullptr);
    if (!src) {
        lua->pushnil(L);
        lua->pushstring(L, "tcc.compile: source must be a string");
        return 2;
    }

    bool use_prelude = true;
    if (lua->type(L, 2) == LUA_TTABLE) {
        lua->getfield(L, 2, "prelude");
        if (lua->type(L, -1) == LUA_TBOOLEAN && !lua->toboolean(L, -1)) {
            use_prelude = false;
        }
        lua->pop(L, 1);
    }

    std::string error;
    TCCState* s = internal::compile(L, src, use_prelude, error);
    if (!s) {
        lua->pushnil(L);
        lua->pushstring(L, error.c_str());
        return 2;
    }

    auto* prog = new Program{s, false};
    push_program_userdata(L, prog);
    return 1;
}

void register_all(lua_State* L) {
    auto lua = g_api->lua;

    s_main_state = L;

    // Metatable for program userdata: __gc + __index -> methods table.
    lua->createtable(L, 0, 2);

    lua->pushcclosure(L, reinterpret_cast<void*>(gc), 0);
    lua->setfield(L, -2, "__gc");

    lua->createtable(L, 0, 1);
    lua->pushcclosure(L, reinterpret_cast<void*>(method_get), 0);
    lua->setfield(L, -2, "get");
    lua->setfield(L, -2, "__index");

    s_metatable_ref = lua->ref(L, LUA_REGISTRYINDEX);

    // The tcc module table.
    lua->createtable(L, 0, 1);

    lua->pushcclosure(L, reinterpret_cast<void*>(compile), 0);
    lua->setfield(L, -2, "compile");

    lua->setfield(L, -2, "tcc");
}

} // namespace api::tcc
