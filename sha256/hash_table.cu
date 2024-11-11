#include <cuda_runtime.h>
#include <cstdio>
#include <device_launch_parameters.h>

#define TABLE_SIZE 1024
#define MAX_ITERATIONS 32

__device__ unsigned int hash1(unsigned int key) {
    return key % TABLE_SIZE;
}

__device__ unsigned int hash2(unsigned int key) {
    return (key / TABLE_SIZE) % TABLE_SIZE;
}

__global__ void cuckooInsert(unsigned int* table1, unsigned int* table2, unsigned int* keys, int numKeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numKeys) return;

    unsigned int key = keys[idx];
    unsigned int pos1 = hash1(key);
    unsigned int pos2 = hash2(key);

    for (int i = 0; i < MAX_ITERATIONS; ++i) {
        // Try to insert into table1
        unsigned int oldKey = atomicExch(&table1[pos1], key);
        if (oldKey == 0) return; // Successfully inserted

        // Try to insert the displaced key into table2
        key = oldKey;
        oldKey = atomicExch(&table2[pos2], key);
        if (oldKey == 0) return; // Successfully inserted

        // Update positions for the next iteration
        key = oldKey;
        pos1 = hash1(key);
        pos2 = hash2(key);
    }

    // If we reach here, insertion failed after MAX_ITERATIONS
    printf("Failed to insert key %u\n", key);
}

int main() {
    // Example usage
    unsigned int* d_table1;
    unsigned int* d_table2;
    unsigned int* d_keys;
    int numKeys = 1000;

    cudaMalloc(&d_table1, TABLE_SIZE * sizeof(unsigned int));
    cudaMalloc(&d_table2, TABLE_SIZE * sizeof(unsigned int));
    cudaMalloc(&d_keys, numKeys * sizeof(unsigned int));

    // Initialize tables and keys...

    int blockSize = 256;
    int numBlocks = (numKeys + blockSize - 1) / blockSize;
    cuckooInsert<<<numBlocks, blockSize>>>(d_table1, d_table2, d_keys, numKeys);

    cudaFree(d_table1);
    cudaFree(d_table2);
    cudaFree(d_keys);

    return 0;
}
