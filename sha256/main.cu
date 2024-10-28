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
const int charset_size = 62; // Length of charset
const size_t password_length = 6;

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
    int hash_idx;
    uint64_t index;
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

        #pragma unroll 11
        for(int i = 4; i < 15; i++) {
            W[i] = 0;
        }
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
            register uint32_t tmp;

            // Calculate S1
            asm("shf.r.wrap.b32 %0, %2, %2, 6;"
                "shf.r.wrap.b32 %1, %2, %2, 11;"
                "xor.b32 %0, %0, %1;"
                "shf.r.wrap.b32 %1, %2, %2, 25;"
                "xor.b32 %0, %0, %1;"
                : "=r"(S1), "=r"(tmp)
                : "r"(e));

            // Calculate S0
            asm("shf.r.wrap.b32 %0, %2, %2, 2;"
                "shf.r.wrap.b32 %1, %2, %2, 13;"
                "xor.b32 %0, %0, %1;"
                "shf.r.wrap.b32 %1, %2, %2, 22;"
                "xor.b32 %0, %0, %1;"
                : "=r"(S0), "=r"(tmp)
                : "r"(a));

            // Optimize choice and majority functions
            register uint32_t ch;
            asm("lop3.b32 %0, %1, %2, %3, 0xCA;" : "=r"(ch) : "r"(e), "r"(f), "r"(g));

            register uint32_t maj;
            asm("lop3.b32 %0, %1, %2, %3, 0xE8;" : "=r"(maj) : "r"(a), "r"(b), "r"(c));


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

    __device__ void update(const uint8_t* input, size_t len) {
        #pragma unroll
        for (size_t i = 0; i < len; i++) {
            data[i] = input[i];
        }
    }

    __device__ void final(uint8_t* hash) {
        transform();
        
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
    unsigned long long* global_start_index,
    int batch_size,
    unsigned long long lowest_unfound_index,
    FoundPassword* found_passwords,
    int* num_found,
    const int* d_hash_data, // Updated to use d_hash_data
    int hash_table_size
) {
    __shared__ uint8_t shared_target[32];
    __shared__ uint8_t shared_salt[8];

    // Load target hash and salt into shared memory
    if (threadIdx.x < 32) {
        shared_target[threadIdx.x] = target_hashes[threadIdx.x];
    }
    if (threadIdx.x < 8) {
        shared_salt[threadIdx.x] = target_salts[threadIdx.x];
    }

   // In kernel:
   uint64_t base_index = lowest_unfound_index + (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    
    __syncthreads();

    #pragma unroll
    for (int i = 0; i < batch_size; i++) {
        uint64_t idx = base_index + i * gridDim.x * blockDim.x;
        if (idx >= total_passwords) return;


        // Generate password using charset
        char password[7];  // 6 chars + null terminator
        for (int j = 0; j < 6; j++) {
            uint32_t char_idx = (idx >> (j * 6)) & 0x3F;
            password[j] = charset[char_idx];
        }
        
        // Combine password and salt
        uint8_t combined[14];
        memcpy(combined, password, 6);
        memcpy(combined + 6, shared_salt, 8);

        // Compute hash using optimized SHA256
        SHA256 sha256;
        uint8_t hash[32];
        sha256.update(combined, 14);
        sha256.final(hash);

        // Compute hash of the candidate hash using the device-side hash function
        // Compute hash of the candidate hash using the device-side hash function
        unsigned int candidate_hash_value = simpleHashDevice(hash, 32);
        int index = candidate_hash_value % hash_table_size;
        // Use linear probing to find a match in the hash table
        while (d_hash_data[index] != -1) {
            int target_index = d_hash_data[index];

            const uint8_t* current_target = &target_hashes[target_index * 32];

            bool match = true;
            #pragma unroll 8
            for (int k = 0; k < 32; k += 4) {
                if (*(uint32_t*)&hash[k] != *(uint32_t*)&current_target[k]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // printf("Found match for hash index %d at index %lu\n", target_index, idx);
                int found_idx = atomicAdd(num_found, 1);
                if (found_idx < MAX_FOUND) {
                    memcpy(found_passwords[found_idx].password, password, 7);
                    memcpy(found_passwords[found_idx].hash, hash, 32);
                    memcpy(found_passwords[found_idx].salt, shared_salt, 8);
                    found_passwords[found_idx].hash_idx = target_index;
                    found_passwords[found_idx].index = idx;
                }
            }
            index = (index + 1) % hash_table_size; // Linear probing
        }
    }
}

int main() {
    // Get device properties
    int maxThreadsPerBlock, maxBlocksPerSM, numSMs;
    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    printf("Device properties:\n");
    printf("- Number of SMs: %d\n", numSMs);
    printf("- Max threads per block: %d\n", maxThreadsPerBlock);
    printf("- Max blocks per SM: %d\n", maxBlocksPerSM);

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

    printf("\nLoaded %d hash-salt pairs\n", num_hashes);

    uint8_t all_target_hashes[MAX_HASHES * 32];
    uint8_t all_target_salts[MAX_HASHES * 8];
    
    for (int i = 0; i < num_hashes; i++) {
        hexToBytes(all_hashes[i].hash, &all_target_hashes[i * 32]);
        hexToBytes(all_hashes[i].salt, &all_target_salts[i * 8]);
    }

    uint8_t *d_target_salts;
    uint8_t *d_target_hashes;
    unsigned long long *d_global_start_index;

    cudaMalloc(&d_target_salts, num_hashes * 8);
    cudaMalloc(&d_target_hashes, num_hashes * 32);
    cudaMalloc(&d_global_start_index, sizeof(unsigned long long));

    cudaMemcpy(d_target_salts, all_target_salts, num_hashes * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hashes, all_target_hashes, num_hashes * 32, cudaMemcpyHostToDevice);

    const int NUM_STREAMS = 100;
    cudaStream_t streams[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; i++) {
        cudaStreamCreate(&streams[i]);
    }

    // Define the size of the hash table
    const int HASH_TABLE_SIZE = 1024; // Adjust based on the number of target hashes

    // Initialize hash table
    std::vector<int> hash_data(HASH_TABLE_SIZE, -1);

    // Populate the hash table using linear probing
    for (int i = 0; i < num_hashes; i++) {
        unsigned int hash_value = simpleHashHost(&all_target_hashes[i * 32], 32);
        int index = hash_value % HASH_TABLE_SIZE;

        // Linear probing to handle collisions
        while (hash_data[index] != -1) {
            index = (index + 1) % HASH_TABLE_SIZE;
        }

        // Store the index of the target hash
        hash_data[index] = i;
    }

    // Allocate and initialize hash table on the device
    int* d_hash_data;
    cudaMalloc(&d_hash_data, HASH_TABLE_SIZE * sizeof(int));
    // Copy data from host to device
    cudaMemcpy(d_hash_data, hash_data.data(), HASH_TABLE_SIZE * sizeof(int), cudaMemcpyHostToDevice);

    
    int blockSize = 128;
    int batch_size = 1;
    int numBlocks = numSMs * maxBlocksPerSM;
    unsigned long long lowest_unfound_index = 0;

    printf("\nKernel configuration:\n");
    printf("- Block size: %d\n", blockSize);
    printf("- Number of blocks: %d\n", numBlocks);
    printf("- Batch size: %d\n", batch_size);
    printf("- Number of streams: %d\n", NUM_STREAMS);

    FoundPassword* d_found_passwords;
    int* d_num_found;
    cudaMalloc(&d_found_passwords, MAX_FOUND * sizeof(FoundPassword));
    cudaMalloc(&d_num_found, sizeof(int));
    cudaMemset(d_num_found, 0, sizeof(int));

    auto start_time = std::chrono::high_resolution_clock::now();

    // Adjust increment to prevent overflow
    uint64_t increment = (uint64_t)NUM_STREAMS * numBlocks * blockSize * batch_size;
    printf("Increment: %lu\n", increment);
    while (lowest_unfound_index < total_passwords) {
        // printf("\rProcessing index: %llu / %llu (%.2f%%)", 
        //        lowest_unfound_index, total_passwords, 
        //         (float)lowest_unfound_index * 100 / total_passwords);
            
        // Launch kernels
        for (int i = 0; i < NUM_STREAMS; i++) {
            find_passwords_optimized_multi<<<numBlocks, blockSize, 0, streams[i]>>>(
                d_target_salts,
                d_target_hashes,
                num_hashes,
                d_global_start_index,
                batch_size,
                lowest_unfound_index + i * numBlocks * blockSize * batch_size,
                d_found_passwords,
                d_num_found,
                d_hash_data,
                HASH_TABLE_SIZE
            );
        }
            
        if (total_passwords - lowest_unfound_index < increment) {
            increment = total_passwords - lowest_unfound_index;
        }
        lowest_unfound_index += increment;
    }
    

    cudaDeviceSynchronize();
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;

    FoundPassword* h_found_passwords = new FoundPassword[MAX_FOUND];
    int h_num_found;
    cudaMemcpy(&h_num_found, d_num_found, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_found_passwords, d_found_passwords, h_num_found * sizeof(FoundPassword), cudaMemcpyDeviceToHost);
    
    // for(int i = 0; i < h_num_found; i++) {
    //     const FoundPassword& fp = h_found_passwords[i];
    //     for(int j = 0; j < 32; j++) printf("%02x", fp.hash[j]);
    //     printf(":");
    //     for(int j = 0; j < 8; j++) printf("%02x", fp.salt[j]);
    //     printf(":%s\n", fp.password);
    // }

    printf("\n\nPerformance metrics:\n");
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
    cudaFree(d_global_start_index);

    return 0;
}