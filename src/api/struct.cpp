#include "struct.hpp"
#include "../globals.hpp"
#include "../util/call-auth.hpp"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace api::cstruct {

// ---- Type system ----

struct TypeInfo {
  size_t size;
  size_t alignment;
};

struct FieldInfo {
  std::string name;
  std::string type_name;
  size_t offset;
  size_t size;      // total size (element_size * count for arrays)
  size_t alignment;
  size_t count;     // 0 = not an array, >0 = array element count
  bool is_string;   // [[string]] attribute - read char[]/char* as string
};

struct StructDef {
  std::string name;
  std::vector<FieldInfo> fields;
  size_t total_size;
  size_t alignment;
  bool is_union;
};

// How to read/write a primitive type
enum class PrimKind { I8, U8, I16, U16, I32, U32, I64, U64, F32, F64 };

static std::unordered_map<std::string, TypeInfo> s_builtin_types;
static std::unordered_map<std::string, PrimKind> s_prim_kinds;
static std::unordered_map<std::string, StructDef> s_structs;

static void init_builtin_types() {
  if (!s_builtin_types.empty())
    return;

  // 1-byte
  s_builtin_types["char"] = {1, 1};
  s_builtin_types["signed char"] = {1, 1};
  s_builtin_types["unsigned char"] = {1, 1};
  s_builtin_types["int8_t"] = {1, 1};
  s_builtin_types["uint8_t"] = {1, 1};
  s_builtin_types["bool"] = {1, 1};

  // 2-byte
  s_builtin_types["short"] = {2, 2};
  s_builtin_types["signed short"] = {2, 2};
  s_builtin_types["unsigned short"] = {2, 2};
  s_builtin_types["int16_t"] = {2, 2};
  s_builtin_types["uint16_t"] = {2, 2};

  // 4-byte
  s_builtin_types["int"] = {4, 4};
  s_builtin_types["signed int"] = {4, 4};
  s_builtin_types["unsigned int"] = {4, 4};
  s_builtin_types["int32_t"] = {4, 4};
  s_builtin_types["uint32_t"] = {4, 4};
  s_builtin_types["long"] = {4, 4}; // MSVC: long is 4 bytes
  s_builtin_types["signed long"] = {4, 4};
  s_builtin_types["unsigned long"] = {4, 4};
  s_builtin_types["float"] = {4, 4};

  // 8-byte
  s_builtin_types["long long"] = {8, 8};
  s_builtin_types["signed long long"] = {8, 8};
  s_builtin_types["unsigned long long"] = {8, 8};
  s_builtin_types["int64_t"] = {8, 8};
  s_builtin_types["uint64_t"] = {8, 8};
  s_builtin_types["double"] = {8, 8};

  // Pointer-sized (x86-64)
  s_builtin_types["size_t"] = {8, 8};
  s_builtin_types["uintptr_t"] = {8, 8};
  s_builtin_types["intptr_t"] = {8, 8};
  s_builtin_types["ptrdiff_t"] = {8, 8};

  // Primitive read/write kinds
  s_prim_kinds["char"] = PrimKind::I8;
  s_prim_kinds["signed char"] = PrimKind::I8;
  s_prim_kinds["int8_t"] = PrimKind::I8;
  s_prim_kinds["unsigned char"] = PrimKind::U8;
  s_prim_kinds["uint8_t"] = PrimKind::U8;
  s_prim_kinds["bool"] = PrimKind::U8;

  s_prim_kinds["short"] = PrimKind::I16;
  s_prim_kinds["signed short"] = PrimKind::I16;
  s_prim_kinds["int16_t"] = PrimKind::I16;
  s_prim_kinds["unsigned short"] = PrimKind::U16;
  s_prim_kinds["uint16_t"] = PrimKind::U16;

  s_prim_kinds["int"] = PrimKind::I32;
  s_prim_kinds["signed int"] = PrimKind::I32;
  s_prim_kinds["int32_t"] = PrimKind::I32;
  s_prim_kinds["long"] = PrimKind::I32;
  s_prim_kinds["signed long"] = PrimKind::I32;
  s_prim_kinds["unsigned int"] = PrimKind::U32;
  s_prim_kinds["uint32_t"] = PrimKind::U32;
  s_prim_kinds["unsigned long"] = PrimKind::U32;

  s_prim_kinds["float"] = PrimKind::F32;

  s_prim_kinds["long long"] = PrimKind::I64;
  s_prim_kinds["signed long long"] = PrimKind::I64;
  s_prim_kinds["int64_t"] = PrimKind::I64;
  s_prim_kinds["intptr_t"] = PrimKind::I64;
  s_prim_kinds["ptrdiff_t"] = PrimKind::I64;
  s_prim_kinds["unsigned long long"] = PrimKind::U64;
  s_prim_kinds["uint64_t"] = PrimKind::U64;
  s_prim_kinds["size_t"] = PrimKind::U64;
  s_prim_kinds["uintptr_t"] = PrimKind::U64;

  s_prim_kinds["double"] = PrimKind::F64;
}

static bool resolve_type(const std::string &name, TypeInfo &out) {
  // Any pointer type is 8 bytes on x86-64
  if (!name.empty() && name.back() == '*') {
    out = {8, 8};
    return true;
  }

  auto it = s_builtin_types.find(name);
  if (it != s_builtin_types.end()) {
    out = it->second;
    return true;
  }

  auto sit = s_structs.find(name);
  if (sit != s_structs.end()) {
    out = {sit->second.total_size, sit->second.alignment};
    return true;
  }

  return false;
}

// ---- Tokenizer ----

enum class TokenType { Word, LBrace, RBrace, LBracket, RBracket, DLBracket, DRBracket, Semi, Star, End };

struct Token {
  TokenType type;
  std::string text;
};

static std::vector<Token> tokenize(const char *input) {
  std::vector<Token> tokens;
  const char *p = input;

  while (*p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
      p++;

    if (!*p)
      break;

    if (*p == '{') {
      tokens.push_back({TokenType::LBrace, "{"});
      p++;
    } else if (*p == '}') {
      tokens.push_back({TokenType::RBrace, "}"});
      p++;
    } else if (*p == ';') {
      tokens.push_back({TokenType::Semi, ";"});
      p++;
    } else if (*p == '[') {
      if (*(p + 1) == '[') {
        tokens.push_back({TokenType::DLBracket, "[["});
        p += 2;
      } else {
        tokens.push_back({TokenType::LBracket, "["});
        p++;
      }
    } else if (*p == ']') {
      if (*(p + 1) == ']') {
        tokens.push_back({TokenType::DRBracket, "]]"});
        p += 2;
      } else {
        tokens.push_back({TokenType::RBracket, "]"});
        p++;
      }
    } else if (*p == '*') {
      tokens.push_back({TokenType::Star, "*"});
      p++;
    } else if (std::isalnum(static_cast<unsigned char>(*p)) || *p == '_') {
      const char *start = p;
      while (*p && (std::isalnum(static_cast<unsigned char>(*p)) || *p == '_'))
        p++;
      tokens.push_back({TokenType::Word, std::string(start, p)});
    } else {
      // Skip unknown characters
      p++;
    }
  }

  tokens.push_back({TokenType::End, ""});
  return tokens;
}

// ---- Parser ----

struct Parser {
  const std::vector<Token> &tokens;
  size_t pos = 0;
  std::string error;

  const Token &peek() const { return tokens[pos]; }
  const Token &advance() { return tokens[pos++]; }

  bool expect(TokenType type) {
    if (peek().type != type) {
      const char *name = type == TokenType::LBrace     ? "{"
                         : type == TokenType::RBrace    ? "}"
                         : type == TokenType::LBracket  ? "["
                         : type == TokenType::RBracket  ? "]"
                         : type == TokenType::DLBracket ? "[["
                         : type == TokenType::DRBracket ? "]]"
                         : type == TokenType::Semi      ? ";"
                         : type == TokenType::Star      ? "*"
                                                        : "word";
      error = std::string("expected '") + name + "' but got '" + peek().text + "'";
      return false;
    }
    advance();
    return true;
  }

  // Parse a type specifier. Handles:
  //   simple:    int, float, MyStruct
  //   qualified: unsigned int, signed char, long long, unsigned long long
  //   pointer:   void*, int*, MyStruct*
  bool parse_type(std::string &out_type) {
    if (peek().type != TokenType::Word) {
      error = "expected type name, got '" + peek().text + "'";
      return false;
    }

    std::string base = peek().text;
    advance();

    if (base == "signed" || base == "unsigned") {
      if (peek().type == TokenType::Word) {
        const auto &next = peek().text;
        if (next == "char" || next == "short" || next == "int" || next == "long") {
          std::string qualifier = next;
          advance();
          if (qualifier == "long" && peek().type == TokenType::Word && peek().text == "long") {
            advance();
            base += " long long";
          } else {
            base += " " + qualifier;
          }
        } else {
          // Next word is the field name, not a type qualifier
          // "unsigned" alone = "unsigned int", "signed" alone = "int"
          base = (base == "unsigned") ? "unsigned int" : "int";
        }
      } else {
        base = (base == "unsigned") ? "unsigned int" : "int";
      }
    } else if (base == "long") {
      if (peek().type == TokenType::Word && peek().text == "long") {
        advance();
        base = "long long";
      }
    }

    // Pointer suffix
    if (peek().type == TokenType::Star) {
      advance();
      out_type = base + "*";
    } else {
      out_type = base;
    }

    return true;
  }

  bool parse_definition(StructDef &def) {
    if (peek().type != TokenType::Word || (peek().text != "struct" && peek().text != "union")) {
      error = "expected 'struct' or 'union'";
      return false;
    }
    def.is_union = (peek().text == "union");
    advance();

    if (peek().type != TokenType::Word) {
      error = "expected type name";
      return false;
    }
    def.name = advance().text;

    if (!expect(TokenType::LBrace))
      return false;

    size_t current_offset = 0;
    size_t max_alignment = 1;
    size_t max_field_end = 0; // for unions: tracks largest field
    bool suppress_next_alignment = false;

    while (peek().type != TokenType::RBrace && peek().type != TokenType::End) {
      // Check for [[attribute]]s before the type
      bool attr_string = false;
      bool attr_unaligned = false;
      while (peek().type == TokenType::DLBracket) {
        advance();
        if (peek().type == TokenType::Word && peek().text == "string") {
          attr_string = true;
          advance();
        } else if (peek().type == TokenType::Word && peek().text == "unaligned") {
          attr_unaligned = true;
          advance();
        } else {
          error = "unknown attribute '" + peek().text + "'";
          return false;
        }
        if (!expect(TokenType::DRBracket))
          return false;
      }

      // Check for padding[N]; - add N bytes to current offset
      // Check for offset[N]; - set absolute offset to N
      if (peek().type == TokenType::Word && (peek().text == "padding" || peek().text == "offset")) {
        bool is_absolute = (peek().text == "offset");
        advance();
        if (!expect(TokenType::LBracket))
          return false;
        if (peek().type != TokenType::Word) {
          error = is_absolute ? "expected offset value" : "expected padding size";
          return false;
        }
        size_t value = std::stoull(peek().text, nullptr, 0);
        advance();
        if (!expect(TokenType::RBracket))
          return false;
        if (!expect(TokenType::Semi))
          return false;
        if (!def.is_union) {
          if (is_absolute) {
            current_offset = value;
            suppress_next_alignment = true;
          } else {
            current_offset += value;
          }
        }
        continue;
      }

      std::string type_name;
      if (!parse_type(type_name))
        return false;

      if (peek().type != TokenType::Word) {
        error = "expected field name, got '" + peek().text + "'";
        return false;
      }
      std::string field_name = advance().text;

      // Check for array suffix: [N]
      size_t array_count = 0;
      if (peek().type == TokenType::LBracket) {
        advance();
        if (peek().type != TokenType::Word) {
          error = "expected array size";
          return false;
        }
        array_count = std::stoull(peek().text, nullptr, 0);
        if (array_count == 0) {
          error = "array size must be > 0";
          return false;
        }
        advance();
        if (!expect(TokenType::RBracket))
          return false;
      }

      if (!expect(TokenType::Semi))
        return false;

      TypeInfo tinfo;
      if (!resolve_type(type_name, tinfo)) {
        error = "unknown type '" + type_name + "'";
        return false;
      }

      size_t field_size = (array_count > 0) ? tinfo.size * array_count : tinfo.size;

      if (def.is_union) {
        // Union: all fields at offset 0
        if (tinfo.alignment > max_alignment)
          max_alignment = tinfo.alignment;
        if (field_size > max_field_end)
          max_field_end = field_size;

        FieldInfo field;
        field.name = field_name;
        field.type_name = type_name;
        field.offset = 0;
        field.size = field_size;
        field.alignment = tinfo.alignment;
        field.count = array_count;
        field.is_string = attr_string;
        def.fields.push_back(std::move(field));
      } else {
        // Struct: sequential layout with alignment
        if (!suppress_next_alignment && !attr_unaligned)
          current_offset = (current_offset + tinfo.alignment - 1) & ~(tinfo.alignment - 1);
        suppress_next_alignment = false;

        if (tinfo.alignment > max_alignment)
          max_alignment = tinfo.alignment;

        FieldInfo field;
        field.name = field_name;
        field.type_name = type_name;
        field.offset = current_offset;
        field.size = field_size;
        field.alignment = tinfo.alignment;
        field.count = array_count;
        field.is_string = attr_string;
        def.fields.push_back(std::move(field));

        current_offset += field_size;
      }
    }

    if (!expect(TokenType::RBrace))
      return false;

    // Optional trailing semicolon
    if (peek().type == TokenType::Semi)
      advance();

    size_t raw_size = def.is_union ? max_field_end : current_offset;
    def.total_size = (raw_size + max_alignment - 1) & ~(max_alignment - 1);
    def.alignment = max_alignment;

    return true;
  }
};

// ---- Memory read/write helpers ----

static void push_primitive(lua_State *L, uintptr_t addr, PrimKind kind) {
  auto lua = g_api->lua;
  switch (kind) {
  case PrimKind::I8:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int8_t *>(addr)));
    break;
  case PrimKind::U8:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint8_t *>(addr)));
    break;
  case PrimKind::I16:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int16_t *>(addr)));
    break;
  case PrimKind::U16:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint16_t *>(addr)));
    break;
  case PrimKind::I32:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int32_t *>(addr)));
    break;
  case PrimKind::U32:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint32_t *>(addr)));
    break;
  case PrimKind::I64:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int64_t *>(addr)));
    break;
  case PrimKind::U64:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint64_t *>(addr)));
    break;
  case PrimKind::F32:
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<float *>(addr)));
    break;
  case PrimKind::F64:
    lua->pushnumber(L, *reinterpret_cast<double *>(addr));
    break;
  }
}

static void write_primitive(uintptr_t addr, PrimKind kind, double value) {
  switch (kind) {
  case PrimKind::I8:
    *reinterpret_cast<int8_t *>(addr) = static_cast<int8_t>(value);
    break;
  case PrimKind::U8:
    *reinterpret_cast<uint8_t *>(addr) = static_cast<uint8_t>(value);
    break;
  case PrimKind::I16:
    *reinterpret_cast<int16_t *>(addr) = static_cast<int16_t>(value);
    break;
  case PrimKind::U16:
    *reinterpret_cast<uint16_t *>(addr) = static_cast<uint16_t>(value);
    break;
  case PrimKind::I32:
    *reinterpret_cast<int32_t *>(addr) = static_cast<int32_t>(value);
    break;
  case PrimKind::U32:
    *reinterpret_cast<uint32_t *>(addr) = static_cast<uint32_t>(value);
    break;
  case PrimKind::I64:
    *reinterpret_cast<int64_t *>(addr) = static_cast<int64_t>(value);
    break;
  case PrimKind::U64:
    *reinterpret_cast<uint64_t *>(addr) = static_cast<uint64_t>(value);
    break;
  case PrimKind::F32:
    *reinterpret_cast<float *>(addr) = static_cast<float>(value);
    break;
  case PrimKind::F64:
    *reinterpret_cast<double *>(addr) = value;
    break;
  }
}

// Forward declaration for recursion
static void push_struct_at(lua_State *L, uintptr_t base, const StructDef &def);
static void write_struct_at(lua_State *L, uintptr_t base, const StructDef &def, int table_idx);

// Push a single value from memory onto the Lua stack
static void push_value_at(lua_State *L, uintptr_t addr, const std::string &type_name) {
  auto lua = g_api->lua;

  // Pointer type
  if (!type_name.empty() && type_name.back() == '*') {
    lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uintptr_t *>(addr)));
    return;
  }

  // Primitive type
  auto pk = s_prim_kinds.find(type_name);
  if (pk != s_prim_kinds.end()) {
    push_primitive(L, addr, pk->second);
    return;
  }

  // Nested struct/union
  auto sit = s_structs.find(type_name);
  if (sit != s_structs.end()) {
    push_struct_at(L, addr, sit->second);
    return;
  }

  // Unknown type - push nil
  lua->pushnil(L);
}

// Push a null-terminated string from memory onto the Lua stack
static void push_string_at(lua_State *L, uintptr_t addr, size_t max_len) {
  auto lua = g_api->lua;
  auto *p = reinterpret_cast<const char *>(addr);
  lua->pushstring(L, p);
}

// Read a whole struct/union into a Lua table
static void push_struct_at(lua_State *L, uintptr_t base, const StructDef &def) {
  auto lua = g_api->lua;
  lua->createtable(L, 0, static_cast<int>(def.fields.size()));

  for (const auto &field : def.fields) {
    uintptr_t addr = base + field.offset;

    if (field.is_string && field.count > 0) {
      // [[string]] char array - read as string up to first null or array length
      push_string_at(L, addr, field.count);
    } else if (field.is_string && !field.type_name.empty() && field.type_name.back() == '*') {
      // [[string]] pointer - dereference and read null-terminated string
      auto ptr = *reinterpret_cast<uintptr_t *>(addr);
      if (ptr != 0) {
        push_string_at(L, ptr, SIZE_MAX);
      } else {
        lua->pushnil(L);
      }
    } else if (field.count > 0) {
      // Array - read each element into a Lua array
      size_t elem_size = field.size / field.count;
      lua->createtable(L, static_cast<int>(field.count), 0);
      for (size_t i = 0; i < field.count; i++) {
        push_value_at(L, addr + i * elem_size, field.type_name);
        lua->rawseti(L, -2, static_cast<int>(i + 1));
      }
    } else {
      push_value_at(L, addr, field.type_name);
    }

    lua->setfield(L, -2, field.name.c_str());
  }
}

// Write a single value from the Lua stack to memory
// Value is at the top of the stack; does NOT pop it.
static void write_value_at(lua_State *L, uintptr_t addr, const std::string &type_name) {
  auto lua = g_api->lua;

  // Pointer type
  if (!type_name.empty() && type_name.back() == '*') {
    *reinterpret_cast<uintptr_t *>(addr) = static_cast<uintptr_t>(lua->tonumber(L, -1));
    return;
  }

  // Primitive type
  auto pk = s_prim_kinds.find(type_name);
  if (pk != s_prim_kinds.end()) {
    write_primitive(addr, pk->second, lua->tonumber(L, -1));
    return;
  }

  // Nested struct/union - expect a table at top of stack
  auto sit = s_structs.find(type_name);
  if (sit != s_structs.end()) {
    write_struct_at(L, addr, sit->second, lua->gettop(L));
    return;
  }
}

// Write a whole struct/union from a Lua table at table_idx
static void write_struct_at(lua_State *L, uintptr_t base, const StructDef &def, int table_idx) {
  auto lua = g_api->lua;

  for (const auto &field : def.fields) {
    uintptr_t addr = base + field.offset;
    lua->getfield(L, table_idx, field.name.c_str());

    if (lua->isnil(L, -1)) {
      lua->pop(L, 1);
      continue; // skip fields not present in the table
    }

    if (field.is_string && field.count > 0 && lua->type(L, -1) == LUA_TSTRING) {
      // [[string]] char array - write string into buffer, null-pad remainder
      size_t len = 0;
      const char *str = lua->tolstring(L, -1, &len);
      auto *dst = reinterpret_cast<char *>(addr);
      size_t copy_len = len < field.count ? len : field.count;
      std::memcpy(dst, str, copy_len);
      if (copy_len < field.count)
        std::memset(dst + copy_len, 0, field.count - copy_len);
    } else if (field.count > 0) {
      // Non-char array - expect a Lua table
      size_t elem_size = field.size / field.count;
      int arr_idx = lua->gettop(L);
      for (size_t i = 0; i < field.count; i++) {
        lua->rawgeti(L, arr_idx, static_cast<int>(i + 1));
        if (!lua->isnil(L, -1))
          write_value_at(L, addr + i * elem_size, field.type_name);
        lua->pop(L, 1);
      }
    } else {
      write_value_at(L, addr, field.type_name);
    }

    lua->pop(L, 1);
  }
}

// ---- Lua API ----

// ffi.struct.define(cdef: string) -> true | false, error_string
static int l_define(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *input = lua->tolstring(L, 1, nullptr);
  if (!input) {
    lua->pushboolean(L, 0);
    lua->pushstring(L, "expected string argument");
    return 2;
  }

  init_builtin_types();

  auto tokens = tokenize(input);
  Parser parser{tokens};
  StructDef def;

  if (!parser.parse_definition(def)) {
    lua->pushboolean(L, 0);
    lua->pushstring(L, parser.error.c_str());
    return 2;
  }

  s_structs[def.name] = std::move(def);
  lua->pushboolean(L, 1);
  return 1;
}

// ffi.struct.sizeof(name: string) -> number | nil
static int l_sizeof(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *name = lua->tolstring(L, 1, nullptr);

  init_builtin_types();

  // Check builtins
  auto bit = s_builtin_types.find(name);
  if (bit != s_builtin_types.end()) {
    lua->pushnumber(L, static_cast<double>(bit->second.size));
    return 1;
  }

  // Check structs
  auto it = s_structs.find(name);
  if (it == s_structs.end())
    return 0;

  lua->pushnumber(L, static_cast<double>(it->second.total_size));
  return 1;
}

// ffi.struct.offsetof(struct_name: string, field_name: string) -> number | nil
static int l_offsetof(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *struct_name = lua->tolstring(L, 1, nullptr);
  const char *field_name = lua->tolstring(L, 2, nullptr);

  auto it = s_structs.find(struct_name);
  if (it == s_structs.end())
    return 0;

  for (const auto &field : it->second.fields) {
    if (field.name == field_name) {
      lua->pushnumber(L, static_cast<double>(field.offset));
      return 1;
    }
  }

  return 0;
}

// ffi.struct.fields(name: string) -> table | nil
// Returns: { {name="x", type="int", offset=0, size=4}, ... }
static int l_fields(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *name = lua->tolstring(L, 1, nullptr);

  auto it = s_structs.find(name);
  if (it == s_structs.end())
    return 0;

  const auto &def = it->second;
  lua->createtable(L, static_cast<int>(def.fields.size()), 0);

  for (size_t i = 0; i < def.fields.size(); i++) {
    const auto &field = def.fields[i];
    lua->createtable(L, 0, field.count > 0 ? 5 : 4);

    lua->pushstring(L, field.name.c_str());
    lua->setfield(L, -2, "name");

    lua->pushstring(L, field.type_name.c_str());
    lua->setfield(L, -2, "type");

    lua->pushnumber(L, static_cast<double>(field.offset));
    lua->setfield(L, -2, "offset");

    lua->pushnumber(L, static_cast<double>(field.size));
    lua->setfield(L, -2, "size");

    if (field.count > 0) {
      lua->pushnumber(L, static_cast<double>(field.count));
      lua->setfield(L, -2, "count");
    }

    if (field.is_string) {
      lua->pushboolean(L, 1);
      lua->setfield(L, -2, "string");
    }

    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }

  return 1;
}

// ffi.struct.read(address: number, type_name: string) -> table | nil
static int l_read(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *name = lua->tolstring(L, 2, nullptr);

  init_builtin_types();

  auto it = s_structs.find(name);
  if (it == s_structs.end())
    return 0;

  push_struct_at(L, addr, it->second);
  return 1;
}

// ffi.struct.write(address: number, type_name: string, table) -> boolean
static int l_write(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *name = lua->tolstring(L, 2, nullptr);

  init_builtin_types();

  auto it = s_structs.find(name);
  if (it == s_structs.end()) {
    lua->pushboolean(L, 0);
    return 1;
  }

  write_struct_at(L, addr, it->second, 3);
  lua->pushboolean(L, 1);
  return 1;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 6);

  lua->pushcclosure(L, reinterpret_cast<void *>(l_define), 0);
  lua->setfield(L, -2, "define");

  lua->pushcclosure(L, reinterpret_cast<void *>(l_sizeof), 0);
  lua->setfield(L, -2, "sizeof");

  lua->pushcclosure(L, reinterpret_cast<void *>(l_offsetof), 0);
  lua->setfield(L, -2, "offsetof");

  lua->pushcclosure(L, reinterpret_cast<void *>(l_fields), 0);
  lua->setfield(L, -2, "fields");

  lua->pushcclosure(L, reinterpret_cast<void *>(l_read), 0);
  lua->setfield(L, -2, "read");

  lua->pushcclosure(L, reinterpret_cast<void *>(l_write), 0);
  lua->setfield(L, -2, "write");

  lua->setfield(L, -2, "struct");
}

} // namespace api::cstruct
