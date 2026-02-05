cmake_minimum_required(VERSION 3.20)

# Parse version from CHANGELOG.md
file(READ "${CMAKE_SOURCE_DIR}/CHANGELOG.md" CHANGELOG_CONTENTS)
string(REGEX MATCH "## \\[([0-9]+\\.[0-9]+\\.[0-9]+)\\]" _ ${CHANGELOG_CONTENTS})
set(PROJECT_VERSION ${CMAKE_MATCH_1})

# TODO: Replace 'lje-module-template' with your project name
project(lje-module-template VERSION ${PROJECT_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate version header
configure_file(
  "${CMAKE_SOURCE_DIR}/src/version.h.in"
  "${CMAKE_SOURCE_DIR}/src/version.h"
)

# Main shared library
add_library(${PROJECT_NAME} SHARED
  src/main.cpp
  # TODO: Add more source files here
)

target_include_directories(${PROJECT_NAME} PRIVATE
  ${CMAKE_SOURCE_DIR}/lje/sdk/include
  # TODO: Add more include directories here
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  # TODO: Add libraries to link here
)
