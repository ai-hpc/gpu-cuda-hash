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



__global__ void find_passwords_optimized_multi(
    const uint8_t* target_salts,
    const uint8_t* target_hashes,
    int num_hashes,
    FoundPassword* found_passwords,
    int* num_found,
    const int* d_hash_data,
    int hash_table_size
) {
    __shared__ uint8_t shared_salt[8];

    if (threadIdx.x < 8) {
        shared_salt[threadIdx.x] = target_salts[threadIdx.x];
    }

    __syncthreads();

    // Calculate thread position for parallel password generation
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t stride = blockDim.x * gridDim.x;
    
    // Process multiple passwords per thread using stride
    for (uint64_t password_idx = tid; password_idx < total_passwords; password_idx += stride) {
        uint64_t idx = password_idx;

        // Combined password and salt array
        uint8_t combined[14];
        
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            combined[i] = charset[idx % 62];
            idx /= 62;
        }

        memcpy(combined + 6, shared_salt, 8);

        // Instantiate SHA256 object
        SHA256 sha256;

        // Compute hash
        uint8_t hash[32];
        sha256.computeHash(combined, hash);

        // Hash table lookup using linear probing
        int index = simpleHashDevice(hash, 32) % hash_table_size;
        
        bool terminate = false;

        while (d_hash_data[index] != -1) {
            const uint8_t* current_target = &target_hashes[d_hash_data[index] * 32];
            bool match = true;
            
            if (terminate) break;
            // printf("Thread %d, tid: %llu, index: %d\n", threadIdx.x, tid, index);
            #pragma unroll 8
            for (int k = 0; k < 32; k += 4) {
                if (*(uint32_t*)&hash[k] != *(uint32_t*)&current_target[k]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                int found_idx = atomicAdd(num_found, 1);
                terminate = true;
                if (found_idx < MAX_FOUND) {
                    // Change char to unsigned char
                    unsigned char password[7] = {combined[0], combined[1], combined[2], 
                        combined[3], combined[4], combined[5], '\0'};
                    memcpy(found_passwords[found_idx].password, password, 7);
                    memcpy(found_passwords[found_idx].hash, hash, 32);
                    memcpy(found_passwords[found_idx].salt, shared_salt, 8);
                }
            }
            index = (index + 1) % hash_table_size;
        }
    }
}

int main() {
    // Get device properties
    int maxThreadsPerBlock, maxBlocksPerSM, numSMs;
    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    // printf("Device properties:\n");
    // printf("- Number of SMs: %d\n", numSMs);
    // printf("- Max threads per block: %d\n", maxThreadsPerBlock);
    // printf("- Max blocks per SM: %d\n", maxBlocksPerSM);

    const int MAX_HASHES = 100;
    struct HashPair {
        char salt[17];
        char hash[65];
    };
    HashPair all_hashes[MAX_HASHES];
    int num_hashes = 0;

    std::ifstream infile("in.txt");
    if (!infile) {
        printf("Error: Unable to open file in.txt\n");
        return 1;
    }

    std::string line;
    while (std::getline(infile, line) && num_hashes < MAX_HASHES) {
        strncpy(all_hashes[num_hashes].salt, line.substr(65, 16).c_str(), 16);
        strncpy(all_hashes[num_hashes].hash, line.substr(0, 64).c_str(), 64);
        all_hashes[num_hashes].salt[16] = '\0';
        all_hashes[num_hashes].hash[64] = '\0';
        num_hashes++;
    }

    uint8_t all_target_hashes[MAX_HASHES * 32];
    uint8_t all_target_salts[MAX_HASHES * 8];
    
    for (int i = 0; i < num_hashes; i++) {
        hexToBytes(all_hashes[i].hash, &all_target_hashes[i * 32]);
        hexToBytes(all_hashes[i].salt, &all_target_salts[i * 8]);
    }

    const int HASH_TABLE_SIZE = 1024; // Adjust based on the number of target hashes

    // Initialize and populate hash table
    std::vector<int> hash_data(HASH_TABLE_SIZE, -1);
    for (int i = 0; i < num_hashes; i++) {
        unsigned int hash_value = simpleHashHost(&all_target_hashes[i * 32], 32);
        int index = hash_value % HASH_TABLE_SIZE;

        while (hash_data[index] != -1) {
            index = (index + 1) % HASH_TABLE_SIZE;
        }
        hash_data[index] = i;
    }

    uint8_t *d_target_salts;
    uint8_t *d_target_hashes;

    cudaMalloc(&d_target_salts, num_hashes * 8);
    cudaMalloc(&d_target_hashes, num_hashes * 32);

    cudaMemcpy(d_target_salts, all_target_salts, num_hashes * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hashes, all_target_hashes, num_hashes * 32, cudaMemcpyHostToDevice);


    // Allocate and initialize hash table on the device
    int* d_hash_data;
    cudaMalloc(&d_hash_data, HASH_TABLE_SIZE * sizeof(int));
    // Copy data from host to device
    cudaMemcpy(d_hash_data, hash_data.data(), HASH_TABLE_SIZE * sizeof(int), cudaMemcpyHostToDevice);

    // Determine the number of threads per block
    int blockSize = 512; // Choose a block size that is a multiple of the warp size
    int numBlocks = numSMs * maxBlocksPerSM; // Maximize the number of blocks

    // printf("\nKernel configuration:\n");
    // printf("- Block size: %d\n", blockSize);
    // printf("- Number of blocks: %d\n", numBlocks);

    FoundPassword* d_found_passwords;
    int* d_num_found;
    cudaMalloc(&d_found_passwords, MAX_FOUND * sizeof(FoundPassword));
    cudaMalloc(&d_num_found, sizeof(int));
    cudaMemset(d_num_found, 0, sizeof(int));

    const int NUM_STREAMS = 100;
    cudaStream_t streams[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++) {
        cudaStreamCreate(&streams[i]);
    }

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);
    auto start_time = std::chrono::high_resolution_clock::now();

        find_passwords_optimized_multi<<<numBlocks, blockSize>>>(
            d_target_salts,
            d_target_hashes,
            num_hashes,
            d_found_passwords,
            d_num_found,
            d_hash_data,
            HASH_TABLE_SIZE
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

    for (int i = 0; i < NUM_STREAMS; i++) {
        cudaStreamDestroy(streams[i]);
    }

    delete[] h_found_passwords;
    cudaFree(d_found_passwords);
    cudaFree(d_num_found);
    cudaFree(d_target_salts);
    cudaFree(d_target_hashes);

    return 0;
}