# Smart Network Traffic Analyzer


# HOWTO build standalone
cd standalone\
cmake -S . -B build\
cmake --build build\
cmake --install build/ --prefix build/install\

The project may be build with  Visual Studio Code CMake extension using attached  `CMakePresets.json` settings.
In both cases the same key directory structure should be produced:

```bash
└── standalone
    ├── build
    │   └── install
    └── src
```
