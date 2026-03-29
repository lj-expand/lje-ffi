cmake_minimum_required(VERSION 3.20)

include(FetchContent)

# Fetch libffi prebuilt binaries
FetchContent_Declare(
  libffi
  URL https://github.com/libffi/libffi/releases/download/v3.5.2/libffi-3.5.2-x86-64bit-msvc-binaries.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(libffi)

# Fetch and build Capstone from source
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_WASM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BPF_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SH_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TRICORE_SUPPORT OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG 5.0.1
)
FetchContent_MakeAvailable(capstone)

# Add MinHook from submodule
add_subdirectory(extern/minhook)

# Parse version from CHANGELOG.md
file(READ "${CMAKE_SOURCE_DIR}/CHANGELOG.md" CHANGELOG_CONTENTS)
string(REGEX MATCH "## \\[([0-9]+\\.[0-9]+\\.[0-9]+)\\]" _ ${CHANGELOG_CONTENTS})
set(PROJECT_VERSION ${CMAKE_MATCH_1})

project(lje-ffi VERSION ${PROJECT_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate version header
configure_file(
  "${CMAKE_SOURCE_DIR}/src/version.h.in"
  "${CMAKE_SOURCE_DIR}/src/version.h"
)

# Main shared library
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
  ${CMAKE_SOURCE_DIR}/lje/sdk/include
  ${libffi_SOURCE_DIR}
  ${capstone_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/extern/minhook/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  ${libffi_SOURCE_DIR}/libffi-8.lib
  psapi
  dbghelp
  capstone
  minhook
)

# Copy libffi DLL to output directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  "${libffi_SOURCE_DIR}/libffi-8.dll"
  $<TARGET_FILE_DIR:${PROJECT_NAME}>
)
