#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include <vector>
#include <unordered_map>

#ifndef SHA256_CUH
#define SHA256_CUH

// Add these color definitions at the top
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

#define MAX_FOUND 1000


__constant__ const unsigned long long total_passwords = 62ULL * 62 * 62 * 62 * 62 * 62;
__constant__ char d_target_salt[16 + 1];
__constant__ uint8_t d_target_hash[32];
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


// Precompute the reciprocal of 62 for division optimization
__constant__ double reciprocal = 1.0 / 62.0;

// __constant__ array for device-side K values
__constant__ static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct FoundPassword {
    char password[7];
    uint8_t hash[32];
    uint8_t salt[8];
};
#include <iostream>
#include <iomanip>
#include <cstdint>


// Right rotate function
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    uint32_t result;
    asm("shf.r.wrap.b32 %0, %1, %1, %2;" : "=r"(result) : "r"(x), "r"(n));
    return result;
}

// SHA-256 hash function
__device__ void sha256(const uint8_t* __restrict__ input, uint8_t* __restrict__ hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t data[64] = {0};
    #pragma unroll
    for (size_t i = 0; i < 14; i++) {
        data[i] = input[i];
    }

    uint32_t W[64];
    W[0] = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    W[1] = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | data[7];
    W[2] = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];
    W[3] = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) | 0x8000;

    *(uint4*)&W[4] = make_uint4(0, 0, 0, 0);
    *(uint4*)&W[8] = make_uint4(0, 0, 0, 0);
    *(uint2*)&W[12] = make_uint2(0, 0);
    W[14] = 0;
    W[15] = 112;

    #pragma unroll 48
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    #pragma unroll 64
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    #pragma unroll 8
    for (int i = 0; i < 8; i++) {
        uint32_t s = state[i];
        hash[i * 4] = s >> 24;
        hash[i * 4 + 1] = s >> 16;
        hash[i * 4 + 2] = s >> 8;
        hash[i * 4 + 3] = s;
    }
}

#endif


// Fix the hexToBytes function to maintain byte order
void hexToBytes(const char* hex, uint8_t* bytes) {
    for (int i = 0; i < strlen(hex)/2; i++) {
        sscanf(hex + i*2, "%2hhx", &bytes[i]);
    }
}

unsigned int xxHash32Host(const uint8_t* data, int length, unsigned int seed = 0) {
    const unsigned int PRIME32_1 = 2654435761U;
    const unsigned int PRIME32_2 = 2246822519U;
    const unsigned int PRIME32_3 = 3266489917U;
    const unsigned int PRIME32_4 = 668265263U;
    const unsigned int PRIME32_5 = 374761393U;

    unsigned int hash;
    int index = 0;

    if (length >= 16) {
        unsigned int v1 = seed + PRIME32_1 + PRIME32_2;
        unsigned int v2 = seed + PRIME32_2;
        unsigned int v3 = seed + 0;
        unsigned int v4 = seed - PRIME32_1;

        const int limit = length - 16;
        do {
            v1 += (*(unsigned int*)(data + index)) * PRIME32_2;
            v1 = (v1 << 13) | (v1 >> (32 - 13));
            v1 *= PRIME32_1;
            index += 4;

            v2 += (*(unsigned int*)(data + index)) * PRIME32_2;
            v2 = (v2 << 13) | (v2 >> (32 - 13));
            v2 *= PRIME32_1;
            index += 4;

            v3 += (*(unsigned int*)(data + index)) * PRIME32_2;
            v3 = (v3 << 13) | (v3 >> (32 - 13));
            v3 *= PRIME32_1;
            index += 4;

            v4 += (*(unsigned int*)(data + index)) * PRIME32_2;
            v4 = (v4 << 13) | (v4 >> (32 - 13));
            v4 *= PRIME32_1;
            index += 4;
        } while (index <= limit);

        hash = ((v1 << 1) | (v1 >> (32 - 1))) +
               ((v2 << 7) | (v2 >> (32 - 7))) +
               ((v3 << 12) | (v3 >> (32 - 12))) +
               ((v4 << 18) | (v4 >> (32 - 18)));
    } else {
        hash = seed + PRIME32_5;
    }

    hash += length;

    while (index <= length - 4) {
        hash += (*(unsigned int*)(data + index)) * PRIME32_3;
        hash = ((hash << 17) | (hash >> (32 - 17))) * PRIME32_4;
        index += 4;
    }

    while (index < length) {
        hash += data[index] * PRIME32_5;
        hash = ((hash << 11) | (hash >> (32 - 11))) * PRIME32_1;
        index++;
    }

    hash ^= hash >> 15;
    hash *= PRIME32_2;
    hash ^= hash >> 13;
    hash *= PRIME32_3;
    hash ^= hash >> 16;

    return hash;
}

__device__ __forceinline__ unsigned int xxHash32Device(const uint8_t* data, int length, unsigned int seed = 0) {
    const unsigned int PRIME32_1 = 2654435761U;
    const unsigned int PRIME32_2 = 2246822519U;
    const unsigned int PRIME32_3 = 3266489917U;
    const unsigned int PRIME32_4 = 668265263U;
    const unsigned int PRIME32_5 = 374761393U;

    unsigned int hash;
    int index = 0;

    if (length >= 16) {
        unsigned int v1 = seed + PRIME32_1 + PRIME32_2;
        unsigned int v2 = seed + PRIME32_2;
        unsigned int v3 = seed + 0;
        unsigned int v4 = seed - PRIME32_1;

        const int limit = length - 16;
        do {
            unsigned int k1 = *(unsigned int*)(data + index);
            v1 += k1 * PRIME32_2;
            v1 = (v1 << 13) | (v1 >> (32 - 13));
            v1 *= PRIME32_1;
            index += 4;

            unsigned int k2 = *(unsigned int*)(data + index);
            v2 += k2 * PRIME32_2;
            v2 = (v2 << 13) | (v2 >> (32 - 13));
            v2 *= PRIME32_1;
            index += 4;

            unsigned int k3 = *(unsigned int*)(data + index);
            v3 += k3 * PRIME32_2;
            v3 = (v3 << 13) | (v3 >> (32 - 13));
            v3 *= PRIME32_1;
            index += 4;

            unsigned int k4 = *(unsigned int*)(data + index);
            v4 += k4 * PRIME32_2;
            v4 = (v4 << 13) | (v4 >> (32 - 13));
            v4 *= PRIME32_1;
            index += 4;
        } while (index <= limit);

        hash = ((v1 << 1) | (v1 >> (32 - 1))) +
               ((v2 << 7) | (v2 >> (32 - 7))) +
               ((v3 << 12) | (v3 >> (32 - 12))) +
               ((v4 << 18) | (v4 >> (32 - 18)));
    } else {
        hash = seed + PRIME32_5;
    }

    hash += length;

    while (index <= length - 4) {
        unsigned int k = *(unsigned int*)(data + index);
        hash += k * PRIME32_3;
        hash = ((hash << 17) | (hash >> (32 - 17))) * PRIME32_4;
        index += 4;
    }

    while (index < length) {
        hash += data[index] * PRIME32_5;
        hash = ((hash << 11) | (hash >> (32 - 11))) * PRIME32_1;
        index++;
    }

    hash ^= hash >> 15;
    hash *= PRIME32_2;
    hash ^= hash >> 13;
    hash *= PRIME32_3;
    hash ^= hash >> 16;

    return hash;
}

__global__ void find_passwords_optimized_multi(
    const uint8_t* __restrict__ target_salts,
    const uint8_t* __restrict__ target_hashes,
    int num_hashes,
    FoundPassword* __restrict__ found_passwords,
    int* __restrict__ num_found,
    const int* __restrict__ d_hash_data,
    int hash_table_size
) {
    __shared__ uint8_t shared_salt[8];



    // Calculate thread position for parallel password generation
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t stride = blockDim.x * gridDim.x;

    // Iterate over each salt
    for (int salt_idx = 0; salt_idx < 10; ++salt_idx) {
        // Load the current salt into shared memory
        if (threadIdx.x < 8) {
            shared_salt[threadIdx.x] = target_salts[salt_idx * 8 + threadIdx.x];
        }

        __syncthreads();
        
        

        // Process multiple passwords per thread using stride
        for (uint64_t password_idx = tid; password_idx < total_passwords; password_idx += stride) {
            uint64_t idx = password_idx;

            // Combined password and salt array
            uint8_t combined[14];
            
            for (int i = 0; i < 6; ++i) {
                combined[i] = charset[idx % 62];
                idx = static_cast<uint64_t>(idx * reciprocal); // Approximate division by 62
            }       
            // Use shared memory for salt
            #pragma unroll
            for (int i = 0; i < 8; ++i) {
                combined[6 + i] = shared_salt[i];
            }

            // Compute hash
            uint8_t hash[32];

            sha256(combined, hash);

            // Iterate over all hashes for the current salt
            // Calculate the hash value for the computed hash
            unsigned int hash_value = xxHash32Device(hash, 8);

            // Determine the index in the hash table
            int index = hash_value % hash_table_size;
            
            // Use linear probing to resolve collisions
            while (d_hash_data[index] != -1) {
                // Get the target hash index from the hash table
                int target_index = d_hash_data[index];
                const uint8_t* current_target = &target_hashes[target_index * 32];
            
                // Compare the computed hash with the target hash
                bool match = true;
                #pragma unroll 8
                for (int k = 0; k < 32; k += 4) {
                    if (*(uint32_t*)&hash[k] != *(uint32_t*)&current_target[k]) {
                        match = false;
                        break;
                    }
                }
            
                if (match) {
                    int found_idx = atomicAdd(num_found, 1);
                    if (found_idx < MAX_FOUND) {
                        // Directly assign characters to the password array
                        found_passwords[found_idx].password[0] = combined[0];
                        found_passwords[found_idx].password[1] = combined[1];
                        found_passwords[found_idx].password[2] = combined[2];
                        found_passwords[found_idx].password[3] = combined[3];
                        found_passwords[found_idx].password[4] = combined[4];
                        found_passwords[found_idx].password[5] = combined[5];
                        found_passwords[found_idx].password[6] = '\0'; // Null-terminate the string

                        // Use a loop to copy the hash and salt, which are larger
                        #pragma unroll
                        for (int i = 0; i < 32; ++i) {
                            found_passwords[found_idx].hash[i] = hash[i];
                        }

                        #pragma unroll
                        for (int i = 0; i < 8; ++i) {
                            found_passwords[found_idx].salt[i] = shared_salt[i];
                        }
                    }
                    break; // Exit loop once a match is found
                }
            
                // Move to the next index in case of a collision
                index = (index + 1) % hash_table_size;
            }
        }
    }
}





int main() {

    int numDevices;
    cudaGetDeviceCount(&numDevices);

    if (numDevices < 1) {
        std::cerr << "No CUDA-capable devices found." << std::endl;
        return 1;
    } else if (numDevices == 1) {
        std::cout << "Using device: " << 0 << std::endl;
    }
    // Get device properties
    int maxThreadsPerBlock, maxBlocksPerSM, numSMs;
    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    // printf("Device properties:\n");
    // printf("- Number of SMs: %d\n", numSMs);
    // printf("- Max threads per block: %d\n", maxThreadsPerBlock);
    // printf("- Max blocks per SM: %d\n", maxBlocksPerSM);

    uint8_t all_target_hashes[10][100][32]; // 10 salts, each with 100 hashes
    uint8_t all_target_salts[10][8];        // 10 unique salts

    std::ifstream infile("in.txt");
    if (!infile) {
        printf("Error: Unable to open file in.txt\n");
        return 1;
    }

    std::string line;
    int salt_index = 0;
    int hash_index = 0;
    while (std::getline(infile, line) && salt_index < 10) {
        // Convert the hash from hex to bytes and store it
        hexToBytes(line.substr(0, 64).c_str(), all_target_hashes[salt_index][hash_index]);

        // Store the salt only once for each group of 100 hashes
        if (hash_index == 0) {
            hexToBytes(line.substr(65, 16).c_str(), all_target_salts[salt_index]);
        }

        hash_index++;
        if (hash_index >= 100) {
            hash_index = 0;
            salt_index++;
        }
    }


    const int HASH_TABLE_SIZE = 19997; // Adjusted to accommodate 1000 target hashes

    // Initialize and populate hash table
    std::vector<int> hash_data(HASH_TABLE_SIZE, -1);

    for (int salt_index = 0; salt_index < 10; salt_index++) {
        for (int hash_index = 0; hash_index < 100; hash_index++) {
            // Calculate the hash value for the current hash
            unsigned int hash_value = xxHash32Host(all_target_hashes[salt_index][hash_index], 8);

            // Determine the index in the hash table
            int index = hash_value % HASH_TABLE_SIZE;

            // Use linear probing to resolve collisions
            while (hash_data[index] != -1) {
                index = (index + 1) % HASH_TABLE_SIZE;
            }

            // Store the index of the hash in the hash table
            hash_data[index] = salt_index * 100 + hash_index;
        }
    }

    // Declare device pointers
    uint8_t *d_target_salts;
    uint8_t *d_target_hashes;

    // Allocate memory for 10 salts, each 8 bytes
    cudaMalloc(&d_target_salts, 10 * 8 * sizeof(uint8_t));

    // Allocate memory for 1000 hashes, each 32 bytes
    cudaMalloc(&d_target_hashes, 1000 * 32 * sizeof(uint8_t));


    // Copy 10 salts, each 8 bytes, from host to device
    cudaMemcpy(d_target_salts, all_target_salts, 10 * 8 * sizeof(uint8_t), cudaMemcpyHostToDevice);

    // Copy 1000 hashes, each 32 bytes, from host to device
    cudaMemcpy(d_target_hashes, all_target_hashes, 1000 * 32 * sizeof(uint8_t), cudaMemcpyHostToDevice);
    
    // Allocate memory for the hash table on the device
    int* d_hash_data;
    cudaMalloc(&d_hash_data, HASH_TABLE_SIZE * sizeof(int));

    // Copy the initialized hash table from host to device
    cudaMemcpy(d_hash_data, hash_data.data(), HASH_TABLE_SIZE * sizeof(int), cudaMemcpyHostToDevice);


    // Determine the number of threads per block
    int blockSize = 512; // Choose a block size that is a multiple of the warp size

    // Calculate the total number of threads needed
    uint64_t totalThreads = total_passwords;

    // Calculate the number of blocks needed to cover all threads
    int numBlocks = (totalThreads + blockSize - 1) / blockSize;

    // Ensure the number of blocks does not exceed the maximum allowed by the device
    numBlocks = min(numBlocks, numSMs * maxBlocksPerSM);

    // printf("Kernel configuration:\n");
    // printf("- Block size: %d\n", blockSize);
    // printf("- Number of blocks: %d\n", numBlocks);

    // Allocate memory for found passwords on the device
    FoundPassword* d_found_passwords;
    cudaMalloc(&d_found_passwords, MAX_FOUND * sizeof(FoundPassword));

    // Allocate memory for the number of found passwords on the device
    int* d_num_found;
    cudaMalloc(&d_num_found, sizeof(int));

    // Initialize the number of found passwords to zero
    cudaMemset(d_num_found, 0, sizeof(int));

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    find_passwords_optimized_multi<<<numBlocks, blockSize>>>(
        d_target_salts,       // Device pointer to the array of salts
        d_target_hashes,      // Device pointer to the array of hashes
        1000,                 // Total number of hashes (10 salts * 100 hashes each)
        d_found_passwords,    // Device pointer to store found passwords
        d_num_found,          // Device pointer to store the number of found passwords
        d_hash_data,          // Device pointer to the hash table data
        HASH_TABLE_SIZE       // Size of the hash table
    );

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA Error: %s\n", cudaGetErrorString(err));
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float gpu_time_ms;
    cudaEventElapsedTime(&gpu_time_ms, start, stop);
    
    cudaDeviceSynchronize();

    // Allocate memory on the host to store found passwords
    FoundPassword* h_found_passwords = new FoundPassword[MAX_FOUND];

    // Variable to store the number of found passwords
    int h_num_found;

    // Copy the number of found passwords from device to host
    cudaMemcpy(&h_num_found, d_num_found, sizeof(int), cudaMemcpyDeviceToHost);

    // Copy the found passwords from device to host
    cudaMemcpy(h_found_passwords, d_found_passwords, h_num_found * sizeof(FoundPassword), cudaMemcpyDeviceToHost);

    // Iterate over the found passwords and print their details
    for (int i = 0; i < h_num_found; i++) {
        const FoundPassword& fp = h_found_passwords[i];
        
        // Print the hash
        for (int j = 0; j < 32; j++) {
            printf("%02x", fp.hash[j]);
        }
        printf(":");
        
        // Print the salt
        for (int j = 0; j < 8; j++) {
            printf("%02x", fp.salt[j]);
        }
        printf(":%s\n", fp.password);
    }

    // Print the total number of found passwords
    printf("\nFound %d passwords\n", h_num_found);



    printf(BOLD CYAN "\nPerformance Metrics:\n" RESET);
    printf("GPU Time: %.2f ms\n", gpu_time_ms);
    // printf("Performance: %.2f GH/s\n", total_passwords / elapsed_seconds.count() / 1e9);


    cudaFree(d_found_passwords);
    cudaFree(d_num_found);
    cudaFree(d_target_salts);
    cudaFree(d_target_hashes);
    cudaFree(d_hash_data);

    return 0;
}