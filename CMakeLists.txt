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

# Fetch prebuilt TinyCC (libtcc) win64 binaries.
# The archive ships libtcc.dll + libtcc.def (but no MSVC import lib) and the
# runtime include/ + lib/ trees. It has no CMakeLists, so MakeAvailable only
# extracts it. The zip's single top-level "tcc/" folder is flattened away by
# FetchContent, so its contents land directly in tcc_SOURCE_DIR.
FetchContent_Declare(
  tcc
  URL https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27-win64-bin.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(tcc)
set(TCC_ROOT "${tcc_SOURCE_DIR}")

# Fetch miniz (single-file, public-domain zip reader). Used at runtime to unpack
# the embedded TinyCC bundle.
FetchContent_Declare(
  miniz
  URL https://github.com/richgel999/miniz/releases/download/3.0.2/miniz-3.0.2.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# The release zip ships no CMakeLists, so MakeAvailable just extracts it.
FetchContent_MakeAvailable(miniz)
file(GLOB MINIZ_C "${miniz_SOURCE_DIR}/miniz.c")
if(NOT MINIZ_C)
  file(GLOB_RECURSE MINIZ_C "${miniz_SOURCE_DIR}/miniz.c")
endif()
list(GET MINIZ_C 0 MINIZ_C)
get_filename_component(MINIZ_DIR "${MINIZ_C}" DIRECTORY)

# Add MinHook from submodule
add_subdirectory(extern/minhook)

# Parse version from CHANGELOG.md
file(READ "${CMAKE_SOURCE_DIR}/CHANGELOG.md" CHANGELOG_CONTENTS)
string(REGEX MATCH "## \\[([0-9]+\\.[0-9]+\\.[0-9]+)\\]" _ ${CHANGELOG_CONTENTS})
set(PROJECT_VERSION ${CMAKE_MATCH_1})

project(lje-ffi VERSION ${PROJECT_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate version header
configure_file(
  "${CMAKE_SOURCE_DIR}/src/version.h.in"
  "${CMAKE_SOURCE_DIR}/src/version.h"
)

# --- libtcc runtime bundle -------------------------------------------------
# We can't assume any user has the same set up, nor if they have lje_sdk.h,
# so everything is bundled into a zip file embedded into the DLL. Quite
# annoying but means we can ensure everything is bundled together in the
# DLL without making users download more stuff (and mess it up).
enable_language(RC)

set(TCC_BUNDLE_STAGE "${CMAKE_BINARY_DIR}/tcc_bundle")
file(REMOVE_RECURSE "${TCC_BUNDLE_STAGE}")
file(MAKE_DIRECTORY "${TCC_BUNDLE_STAGE}")
file(COPY "${TCC_ROOT}/include"    DESTINATION "${TCC_BUNDLE_STAGE}")
file(COPY "${TCC_ROOT}/lib"        DESTINATION "${TCC_BUNDLE_STAGE}")
file(COPY "${TCC_ROOT}/libtcc.dll" DESTINATION "${TCC_BUNDLE_STAGE}")
# The JIT prelude does #include <lje_sdk.h>, so ship it inside the headers tree.
file(COPY "${CMAKE_SOURCE_DIR}/lje/sdk/include/lje_sdk.h"
     DESTINATION "${TCC_BUNDLE_STAGE}/include")

set(TCC_BUNDLE_ZIP "${CMAKE_BINARY_DIR}/tcc_bundle.zip")
execute_process(
  COMMAND ${CMAKE_COMMAND} -E tar "cf" "${TCC_BUNDLE_ZIP}" --format=zip .
  WORKING_DIRECTORY "${TCC_BUNDLE_STAGE}"
  RESULT_VARIABLE _tcc_bundle_result
)
if(NOT _tcc_bundle_result EQUAL 0)
  message(FATAL_ERROR "Failed to create tcc runtime bundle zip")
endif()

# Generate the .rc that embeds the zip (TCC_BUNDLE_ZIP is substituted in).
configure_file(
  "${CMAKE_SOURCE_DIR}/src/tcc_bundle.rc.in"
  "${CMAKE_BINARY_DIR}/tcc_bundle.rc"
  @ONLY
)
# ---------------------------------------------------------------------------

# Main shared library
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.cpp)

add_library(${PROJECT_NAME} SHARED
  ${SOURCES}
  ${MINIZ_C}
  "${CMAKE_BINARY_DIR}/tcc_bundle.rc"
)

target_include_directories(${PROJECT_NAME} PRIVATE
  ${CMAKE_SOURCE_DIR}/lje/sdk/include
  ${libffi_SOURCE_DIR}
  ${capstone_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/extern/minhook/include
  ${TCC_ROOT}/libtcc   # libtcc.h - for TCCState + tcc_* signatures (header only)
  ${MINIZ_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  ${libffi_SOURCE_DIR}/libffi-8.lib
  psapi
  dbghelp
  capstone
  minhook
)

# Cache dir for the unpacked tcc runtime is keyed on the module version.
target_compile_definitions(${PROJECT_NAME} PRIVATE
  TCC_BUNDLE_VERSION="${PROJECT_VERSION}"
)

# Copy libffi DLL to output directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  "${libffi_SOURCE_DIR}/libffi-8.dll"
  $<TARGET_FILE_DIR:${PROJECT_NAME}>
)
