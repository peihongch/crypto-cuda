cmake_minimum_required(VERSION 3.18)
project(HashLibrary LANGUAGES CUDA CXX)

# Add object files (not executables, just object files)
add_library(cudahashlib STATIC
    sha.h

    hmac.cu
    isha.cu

    sha1.cu

    sha224-256.cu
    sha384-512.cu
    usha.cu

    xts.cu
    xts.cuh

    aes.cu
    aes.cuh
)
target_link_libraries(cudahashlib PRIVATE CUDA::cudart_static)
set_target_properties(cudahashlib PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)