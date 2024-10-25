#include <stdio.h>
#include <stdint.h>
#include <cuda_runtime.h>

__constant__ uint32_t K[64] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class SHA256 {
private:
    uint32_t state[8];
    uint8_t data[64];

    __device__ static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ void transform() {
        uint32_t W[64];
        
        // Initial message schedule setup
        printf("\nInitial Message Schedule:\n");
        W[0] = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8) | data[3];
        
        W[1] = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
            ((uint32_t)data[6] << 8) | data[7];
        
        W[2] = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
            ((uint32_t)data[10] << 8) | data[11];
        
        W[3] = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) |
            0x8000;

        printf("W[0] = %08x\n", W[0]);
        printf("W[1] = %08x\n", W[1]);
        printf("W[2] = %08x\n", W[2]);
        printf("W[3] = %08x\n", W[3]);

        printf("\nZero Padding:\n");
        #pragma unroll 11
        for(int i = 4; i < 15; i++) {
            W[i] = 0;
            printf("W[%2d] = %08x\n", i, W[i]);
        }
        W[15] = 112;
        printf("W[15] = %08x\n", W[15]);

        printf("\nExtended Message Schedule:\n");
        #pragma unroll 48
        for(int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
            printf("W[%2d] = %08x\n", i, W[i]);
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        printf("\nCompression Function Rounds:\n");
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

        printf("\nFinal State After Transform:\n");
        for (int i = 0; i < 8; i++) {
            printf("%08x ", state[i]);
        }
        printf("\n");
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



__global__ void test_sha256_debug(const char* input, size_t input_len, const uint8_t* salt, size_t salt_len) {
    SHA256 sha256;
    uint8_t hash[32];
    uint8_t combined[14];  // Fixed size for 6-byte input + 8-byte salt

    // Combine input and salt in one step
    #pragma unroll 6
    for (size_t i = 0; i < input_len; i++) {
        combined[i] = input[i];
    }
    
    #pragma unroll 8
    for (size_t i = 0; i < salt_len; i++) {
        combined[i + input_len] = salt[i];
    }

    // Single update with combined data
    sha256.update(combined, 14);
    sha256.final(hash);
}

// 125b337ce16cd97a15ec5e8e652474adfc87b8f91a33b81f46a9b12e6ee2464b:0e8b22dfc589e87a:7B7nRA

int main() {
    const char* test_input = "7B7nRA";
    const uint8_t test_salt[] = {0x0e, 0x8b, 0x22, 0xdf, 0xc5, 0x89, 0xe8, 0x7a};
    
    char* d_input;
    uint8_t* d_salt;
    
    cudaMalloc(&d_input, 6);
    cudaMalloc(&d_salt, 8);
    
    cudaMemcpy(d_input, test_input, 6, cudaMemcpyHostToDevice);
    cudaMemcpy(d_salt, test_salt, 8, cudaMemcpyHostToDevice);
    
    test_sha256_debug<<<1,1>>>(d_input, 6, d_salt, 8);
    cudaDeviceSynchronize();
    
    cudaFree(d_input);
    cudaFree(d_salt);
    return 0;
}