# Smart Network Traffic Analyzer


# HOWTO build standalone
cd standalone\
cmake -S . -B build\
cmake --build build\
cmake --install build/ --prefix build/install

The project may be build with  Visual Studio Code CMake extension using attached  `CMakePresets.json` settings.
In both cases the same key directory structure should be produced:

```bash
└── standalone
    ├── build
    │   └── install
    └── src
```
## Running packet capture 
Example packet dumping on eth0 with 1s sampling window and 5s probing interval:
```bash
sudo ./build/src/smart_nta 1000 5000 eth0
```
