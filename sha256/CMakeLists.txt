cmake_minimum_required(VERSION 3.18)
project(cuCollections_main LANGUAGES CXX CUDA)

find_package(CUDA REQUIRED)

# Check for extended lambda support
check_cuda_compile_features(cuda_extended_lambda "--extended-lambda")

# Add cuCollections source directory
add_subdirectory(cuCollections)

# Create an main executable
add_executable(main main.cu)

# Link cuCollections library
target_link_libraries(main cuco)

# Set CUDA properties (conditionally add extended lambda flag)
if(cuda_extended_lambda)
    set_target_properties(main PROPERTIES
        CUDA_ARCHITECTURES 86  # Replace with your desired architecture
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_NVCC_FLAGS "-O3 -use_fast_math --expt-extended-lambda"
    )
else()
    message(WARNING "CUDA extended lambda feature not supported. Compilation might fail.")
endif()
