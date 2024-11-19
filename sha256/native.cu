#include <iostream>
#include <immintrin.h> // For AVX
#include <cuda_runtime.h>

// CUDA kernel for vector addition
__global__ void add_arrays_cuda(const float* a, const float* b, float* result, int size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < size) {
        result[idx] = a[idx] + b[idx];
    }
}

// Host function using AVX
void add_arrays_avx(const float* a, const float* b, float* result, int size) {
    int i;
    // Process 8 floats at a time using AVX
    for (i = 0; i <= size - 8; i += 8) {
        __m256 vec_a = _mm256_loadu_ps(&a[i]);
        __m256 vec_b = _mm256_loadu_ps(&b[i]);
        __m256 vec_result = _mm256_add_ps(vec_a, vec_b);
        _mm256_storeu_ps(&result[i], vec_result);
    }

    // Handle any remaining elements
    for (; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}

int main() {
    const int size = 16; // Example size
    const int bytes = size * sizeof(float);

    // Host arrays
    float h_a[size] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f,
                       9.0f, 10.0f, 11.0f, 12.0f, 13.0f, 14.0f, 15.0f, 16.0f};
    float h_b[size] = {16.0f, 15.0f, 14.0f, 13.0f, 12.0f, 11.0f, 10.0f, 9.0f,
                       8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    float h_result[size] = {0};

    // Device arrays
    float *d_a, *d_b, *d_result;

    // Allocate device memory
    cudaMalloc((void**)&d_a, bytes);
    cudaMalloc((void**)&d_b, bytes);
    cudaMalloc((void**)&d_result, bytes);

    // Copy data from host to device
    cudaMemcpy(d_a, h_a, bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, h_b, bytes, cudaMemcpyHostToDevice);

    // Launch CUDA kernel
    int threadsPerBlock = 16;
    int blocksPerGrid = (size + threadsPerBlock - 1) / threadsPerBlock;
    add_arrays_cuda<<<blocksPerGrid, threadsPerBlock>>>(d_a, d_b, d_result, size);

    // Copy result back to host
    cudaMemcpy(h_result, d_result, bytes, cudaMemcpyDeviceToHost);

    // Print CUDA results
    std::cout << "CUDA Results:" << std::endl;
    for (int i = 0; i < size; i++) {
        std::cout << "result[" << i << "] = " << h_result[i] << std::endl;
    }

    // Use AVX for addition on the host
    float avx_result[size] = {0};
    add_arrays_avx(h_a, h_b, avx_result, size);

    // Print AVX results
    std::cout << "AVX Results:" << std::endl;
    for (int i = 0; i < size; i++) {
        std::cout << "avx_result[" << i << "] = " << avx_result[i] << std::endl;
    }

    // Free device memory
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_result);

    return 0;
}
