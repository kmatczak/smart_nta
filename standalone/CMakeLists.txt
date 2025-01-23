cmake_minimum_required(VERSION 3.12)
project(smart_network_traffic_analyzer)

# Set the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_INSTALL_PREFIX "install")

# Add subdirectories
#add_subdirectory(lib)
add_subdirectory(src)

# Installation rules
install(DIRECTORY include/ DESTINATION include FILES_MATCHING PATTERN "*.h")
