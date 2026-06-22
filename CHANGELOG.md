# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-21

### Added

- Added documentation.

## [1.0.0] - 2026-06-11

### Added

- TCC module, to invoke the Tiny C Compiler and interact with C programs
- Detour module, to create C-based detours without needing to write a custom binary module
- `ffi.mem.upvalue`, allows you to get upvalues of C functions as well
- `ffi.mem.function_to_ptr`, grabs C function pointers as well

### Changed

- Set up a new zip bundle system so we can distribute binaries while only shipping one DLL.

### Removed

- Remove old call auth system for LJE 1

## [0.2.0] - 2026-03-28

### Added

- Distribute libffi-8.dll

## [0.1.0] - YYYY-MM-DD

### Added

- Initial release
- TODO: Add features here
