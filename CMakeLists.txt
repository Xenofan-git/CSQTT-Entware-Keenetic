cmake_minimum_required(VERSION 3.20)
project(wpe-auth C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WPE REQUIRED IMPORTED_TARGET wpe-webkit-2.0)
pkg_check_modules(WPE_PLATFORM REQUIRED IMPORTED_TARGET wpe-platform-2.0)

add_executable(wpe-auth src/main.c)
target_link_libraries(wpe-auth PRIVATE PkgConfig::WPE PkgConfig::WPE_PLATFORM)

# WPE auth probe used by the CSQTT Entware integration.
