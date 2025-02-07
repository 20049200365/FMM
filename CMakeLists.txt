cmake_minimum_required(VERSION 3.29)
project(Version_1)

set(CMAKE_CXX_STANDARD 20)

include_directories(tool)

add_executable(Version_1 FMM_CODE.cpp)
add_executable(EFMM_CODE EFMM_CODE.cpp)
target_link_libraries(EFMM_CODE -lssl -lcrypto)