# lje-module-template

An [LJE](https://github.com/lj-expand/lj-expand) binary module.

## Usage

1. Click "Use this template" on GitHub (or clone and rename)
2. Find/replace `lje-module-template` with your project name in:
   - `CMakeLists.txt` (project name)
   - `.github/workflows/release.yml` (DLL filename)
   - This `README.md`
3. Update `CHANGELOG.md` with the release date
4. Initialize the LJE submodule: `git submodule update --init --recursive`
5. Start coding in `src/main.cpp`

## Building

```bash
cmake --preset x64-windows-rel
cmake --build --preset x64-windows-rel
```

Output: `build/x64-windows-rel/lje-module-template.dll`

## License

TODO: Add license
