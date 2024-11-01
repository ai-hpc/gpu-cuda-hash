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
    
class SHA256 {
private:
    uint32_t state[8];
    uint8_t data[64];

    __device__ __forceinline__ static uint32_t rotr(uint32_t x, uint32_t n) {
        uint32_t result;
        asm("shf.r.wrap.b32 %0, %1, %1, %2;" : "=r"(result) : "r"(x), "r"(n));
        return result;
    }

    __device__ void transform() {
        uint32_t W[64];
        
        // Initial message schedule setup
        W[0] = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8) | data[3];
        
        W[1] = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
            ((uint32_t)data[6] << 8) | data[7];
        
        W[2] = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
            ((uint32_t)data[10] << 8) | data[11];
        
        W[3] = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) | 0x8000;

        // Use 32-bit writes to zero out multiple elements at once
        *(uint4*)&W[4] = make_uint4(0, 0, 0, 0);  // Zeros W[4] through W[7]
        *(uint4*)&W[8] = make_uint4(0, 0, 0, 0);  // Zeros W[8] through W[11]
        *(uint2*)&W[12] = make_uint2(0, 0);       // Zeros W[12] through W[13]
        W[14] = 0;    
        W[15] = 112;

        #pragma unroll 48
        for(int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
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
        for(int i = 0; i < 64; i++) {
            // Pre-calculate rotations for better instruction pipelining
            register uint32_t S1, S0;

            // Calculate S1
            S1 = (e >> 6) | (e << (32 - 6));
            S1 ^= (e >> 11) | (e << (32 - 11));
            S1 ^= (e >> 25) | (e << (32 - 25));
            
            // Calculate S0
            S0 = (a >> 2) | (a << (32 - 2));
            S0 ^= (a >> 13) | (a << (32 - 13));
            S0 ^= (a >> 22) | (a << (32 - 22));
            

            register uint32_t ch;
            register uint32_t maj;
            
            // Choice function
            ch = (e & f) ^ (~e & g);
            
            // Majority function 
            maj = (a & b) ^ (a & c) ^ (b & c);
            

            // Combine calculations efficiently
            register uint32_t temp1 = h + S1 + ch + K[i] + W[i];
            register uint32_t temp2 = S0 + maj;

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
    }

public:
    __device__ SHA256() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

    __device__ void computeHash(const uint8_t* input, uint8_t* hash) {
        // Update the data array with the input
        #pragma unroll
        for (size_t i = 0; i < 14; i++) {
            data[i] = input[i];
        }
    
        // Perform the transformation
        transform();
    
        // Finalize the hash computation
        #pragma unroll 8
        for (int i = 0; i < 8; i++) {
            uint32_t s = state[i];
            hash[i*4] = s >> 24;
            hash[i*4 + 1] = s >> 16;
            hash[i*4 + 2] = s >> 8;
            hash[i*4 + 3] = s;
        }
    }
};

#endif


// Fix the hexToBytes function to maintain byte order
void hexToBytes(const char* hex, uint8_t* bytes) {
    for (int i = 0; i < strlen(hex)/2; i++) {
        sscanf(hex + i*2, "%2hhx", &bytes[i]);
    }
}

// Host-side hash function
unsigned int simpleHashHost(const uint8_t* hash, int length) {
    unsigned int h = 0;
    for (int i = 0; i < length; i++) {
        h = h * 31 + hash[i];
    }
    return h;
}

// Device-side hash function
__device__ unsigned int simpleHashDevice(const uint8_t* hash, int length) {
    unsigned int h = 0;
    for (int i = 0; i < length; i++) {
        h = h * 31 + hash[i];
    }
    return h;
}



// Add at the top with other defines
#define HASH_TABLE_SIZE 2048

// Structure definition
struct SaltGroupSoA {
    uint8_t* salts;
    uint8_t* hashes;
    int count;
};

__global__ void find_passwords_multiple_salt_groups(
    const SaltGroupSoA* __restrict__ salt_groups,
    const int num_salt_groups,
    FoundPassword* __restrict__ found_passwords,
    int* __restrict__ num_found
) {
    const uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t stride = blockDim.x * gridDim.x;
    
    SHA256 sha256;
    uint8_t combined[14];

    for (int group_idx = 0; group_idx < 1; group_idx++) {
        const SaltGroupSoA& group = salt_groups[group_idx];
        
        // Load salt into shared memory
        __shared__ uint8_t shared_salt[8];
        if (threadIdx.x < 8) {
            shared_salt[threadIdx.x] = group.salts[threadIdx.x];
        }
        __syncthreads();

        // // Print the salt group information
        // if (tid == 0) { // To avoid excessive printing, only let one thread print this
        //     printf("SaltGroupSoA %d:\n", group_idx);
        //     printf("  Salts: ");
        //     for (int i = 0; i < 8; i++) {
        //         printf("%02x", group.salts[i]);
        //     }
        //     printf("\n  Hashes:\n");
        //     for (int i = 0; i < group.count; i++) {
        //         printf("  Hash %d: ", i);
        //         for (int j = 0; j < 32; j++) {
        //             printf("%02x", group.hashes[i * 32 + j]);
        //         }
        //         printf("\n");
        //     }
        // }
        // __syncthreads();

        memcpy(combined + 6, shared_salt, 8);

        for (uint64_t password_idx = tid; password_idx < total_passwords; password_idx += stride) {
            uint64_t idx = password_idx;
            
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                combined[i] = charset[idx % 62];
                idx /= 62;
            }

                        // // Debug: Print the combined array before hashing
                        // printf("Password + Salt: ");
                        // for (int i = 0; i < 14; i++) {
                        //     printf("%02x", combined[i]);
                        // }
                        // printf("\n");


            uint8_t hash[32];
            sha256.computeHash(combined, hash);

            // // Print the computed hash
            // printf("Computed hash for password %s: ", combined);
            // for (int k = 0; k < 32; k++) {
            //     printf("%02x", hash[k]);
            // }
            // printf("\n");
            
            for (int i = 0; i < group.count; i++) {
                const uint8_t* target_hash = &group.hashes[i * 32];
                bool match = true;
                
                #pragma unroll 8
                for (int k = 0; k < 32; k++) {
                    if (hash[k] != target_hash[k]) {
                        match = false;
                        break;
                    }
                }

                                // Print the target_hash
                                if (idx%100000 == 0) { // To avoid excessive printing, only let one thread print this
                                    printf("Target hash for group %d, index %ld: ", group_idx, password_idx);
                                    for (int k = 0; k < 32; k++) {
                                        printf("%02x", hash[k]);
                                    }
                                    printf("\n");
                                    for (int k = 0; k < 32; k++) {
                                        printf("%02x", target_hash[k]);
                                    }
                                    printf("\n");
                                }

                if (match) {
                    printf("Match found: Password = %s, Group = %d, Index = %llu\n", combined, group_idx, password_idx);
                    int found_idx = atomicAdd(num_found, 1);
                    if (found_idx < MAX_FOUND) {
                        memcpy(found_passwords[found_idx].password, combined, 6);
                        found_passwords[found_idx].password[6] = '\0';
                        memcpy(found_passwords[found_idx].hash, hash, 32);
                        memcpy(found_passwords[found_idx].salt, shared_salt, 8);
                    }
                    break;
                } 
                // else {
                //     if(password_idx % 10000000 == 0) {
                //         printf("No match: Password = %s, Group = %d, Index = %llu\n", combined, group_idx, password_idx);
                //     }
                // }
            }
        }
    }
}

bool isValidHex(const std::string& str) {
    return str.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

int main() {
    int maxThreadsPerBlock, maxBlocksPerSM, numSMs;
    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    const int MAX_HASHES = 1000;
    const int NUM_SALT_GROUPS = 10;

    // Allocate pinned memory for salt groups
    SaltGroupSoA* h_salt_groups = new SaltGroupSoA[NUM_SALT_GROUPS];

    for (int i = 0; i < NUM_SALT_GROUPS; i++) {
        cudaHostAlloc(&h_salt_groups[i].salts, 8, cudaHostAllocDefault);
        cudaHostAlloc(&h_salt_groups[i].hashes, 32 * 100, cudaHostAllocDefault);
        h_salt_groups[i].count = 0;
    }

    std::ifstream infile("in.txt");
    if (!infile) {
        printf("Error: Unable to open file in.txt\n");
        return 1;
    }

    int num_hashes = 0;
    std::string line;
    while (std::getline(infile, line) && num_hashes < MAX_HASHES) {
        std::string hash_str = line.substr(0, 64);
        std::string salt_str = line.substr(65, 16);
    
 
        int group_idx = num_hashes / 100;

    
        hexToBytes(salt_str.c_str(), h_salt_groups[group_idx].salts);
        hexToBytes(hash_str.c_str(), 
        h_salt_groups[group_idx].hashes + (h_salt_groups[group_idx].count * 32));
        h_salt_groups[group_idx].count++;
        num_hashes++;
    }
    

    FoundPassword* d_found_passwords;
    int* d_num_found;
    cudaMalloc(&d_found_passwords, MAX_FOUND * sizeof(FoundPassword));
    cudaMalloc(&d_num_found, sizeof(int));
    cudaMemset(d_num_found, 0, sizeof(int));

    // dim3 block(256);
    // dim3 grid(numSMs * maxBlocksPerSM);
    int block = 256; // Choose a block size that is a multiple of the warp size
    int grid = numSMs * maxBlocksPerSM; // Maximize the number of blocks

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);
    auto start_time = std::chrono::high_resolution_clock::now();

    // Allocate host memory for SaltGroupSoA structures
    SaltGroupSoA* h_salt_groups_device = new SaltGroupSoA[NUM_SALT_GROUPS];

    // Allocate device memory for SaltGroupSoA structures
    SaltGroupSoA* d_salt_groups;
    cudaError_t err = cudaMalloc(&d_salt_groups, NUM_SALT_GROUPS * sizeof(SaltGroupSoA));
    if (err != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(err));
        return;
    }

    for (int i = 0; i < NUM_SALT_GROUPS; i++) {
        // Allocate device memory for salts and hashes
        cudaMalloc(&h_salt_groups_device[i].salts, 8);
        cudaMalloc(&h_salt_groups_device[i].hashes, 32 * h_salt_groups[i].count);

        // Copy salts and hashes from host to device
        cudaMemcpy(h_salt_groups_device[i].salts, h_salt_groups[i].salts, 8, cudaMemcpyHostToDevice);
        cudaMemcpy(h_salt_groups_device[i].hashes, h_salt_groups[i].hashes, 32 * h_salt_groups[i].count, cudaMemcpyHostToDevice);

        // Set the count
        h_salt_groups_device[i].count = h_salt_groups[i].count;
    }

    // Copy the host SaltGroupSoA array to the device
    cudaMemcpy(d_salt_groups, h_salt_groups_device, NUM_SALT_GROUPS * sizeof(SaltGroupSoA), cudaMemcpyHostToDevice);


    find_passwords_multiple_salt_groups<<<grid, block>>>(
        d_salt_groups,
        NUM_SALT_GROUPS, // num_salt_groups
        d_found_passwords,
        d_num_found
    );

    cudaDeviceSynchronize();

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float gpu_time_ms;
    cudaEventElapsedTime(&gpu_time_ms, start, stop);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;

    FoundPassword* h_found_passwords = new FoundPassword[MAX_FOUND];
    int h_num_found;
    cudaMemcpy(&h_num_found, d_num_found, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_found_passwords, d_found_passwords, h_num_found * sizeof(FoundPassword), cudaMemcpyDeviceToHost);

    for(int i = 0; i < h_num_found; i++) {
        const FoundPassword& fp = h_found_passwords[i];
        for(int j = 0; j < 32; j++) printf("%02x", fp.hash[j]);
        printf(":");
        for(int j = 0; j < 8; j++) printf("%02x", fp.salt[j]);
        printf(":%s\n", fp.password);
    }

    printf("\nFound %d passwords\n", h_num_found);
    printf(BOLD CYAN "\nPerformance Metrics:\n" RESET);
    printf("GPU Time: %.2f ms\n", gpu_time_ms);
    printf("Total time: %.2f seconds\n", elapsed_seconds.count());
    printf("Performance: %.2f GH/s\n", total_passwords / elapsed_seconds.count() / 1e9);

    // Cleanup
    for (int i = 0; i < NUM_SALT_GROUPS; i++) {
        cudaFreeHost(h_salt_groups[i].salts);
        cudaFreeHost(h_salt_groups[i].hashes);
    }
    cudaFree(d_salt_groups);
    delete[] h_salt_groups;
    delete[] h_salt_groups_device;
    delete[] h_found_passwords;
    cudaFree(d_found_passwords);
    cudaFree(d_num_found);

    return 0;
}

