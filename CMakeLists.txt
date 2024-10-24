cmake_minimum_required(VERSION 3.18)
project(sha-hmac-cuda LANGUAGES CXX CUDA)

# Enable CUDA standard and position independent code
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CUDA_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin/release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin/debug)

find_package(CUDAToolkit 12 EXACT REQUIRED)
include_directories(SYSTEM ${CUDAToolkit_INCLUDE_DIRS})

# Debug and Release specific flags
if(WIN32)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>)
endif()

set(CUDA_NVCC_FLAGS_DEBUG -g -G)
set(CMAKE_CUDA_FLAGS "-rdc=true")

# Set global CUDA properties
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)
set(CMAKE_CUDA_RESOLVE_DEVICE_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Specify source directories for hash functions
add_subdirectory(hash)
include_directories(hash)

# Build gaes_xts executable
add_executable(aes_xts_test aes_xts_test.cu)
target_link_libraries(aes_xts_test PRIVATE cudahashlib)

# Build ghmac_sha executable
add_executable(hmac_sha_test hmac_sha_test.cu)
target_link_libraries(hmac_sha_test PRIVATE cudahashlib)

# Build gxts_hmac executable
add_executable(xts_hmac_test xts_hmac_test.cu)
target_link_libraries(xts_hmac_test PRIVATE cudahashlib)

add_executable(sha_test sha_test.cpp)
target_link_libraries(sha_test PRIVATE cudahashlib)

add_executable(isha_test isha_test.cu)
target_link_libraries(isha_test PRIVATE cudahashlib)
