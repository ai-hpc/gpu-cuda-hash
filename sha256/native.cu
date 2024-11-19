#include <iostream>
#include <cstring>
#include <chrono>
#include <immintrin.h> // For AVX and AVX2 intrinsics

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

const uint32_t k[64] = {
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
    0x19b4b4b5, 0x1e376c4f, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_init(uint32_t* state) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

void sha256_transform(uint32_t* state, const uint8_t* data) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | 
               (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    }

    for (int i = 16; i < 64; ++i) {
        w[i] = w[i - 16] + (w[i - 7]) +
               ((w[i - 15] >> 7) | (w[i - 15] << (32 - 7))) +
               ((w[i - 2] >> 17) | (w[i - 2] << (32 - 17)));
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + ((e >> 6) | (e << (32 - 6))) + 
                        ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t t2 = ((a >> 2) | (a << (32 - 2))) + 
                       ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
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

void sha256_final(uint32_t* state, const uint8_t* data, size_t length, uint8_t* hash) {
    uint8_t buffer[SHA256_BLOCK_SIZE] = {0};
    size_t i = 0;

    for (; i + SHA256_BLOCK_SIZE <= length; i += SHA256_BLOCK_SIZE) {
        sha256_transform(state, data + i);
    }

    memcpy(buffer, data + i, length - i);
    buffer[length - i] = 0x80;

    if (length % SHA256_BLOCK_SIZE > SHA256_BLOCK_SIZE - 9) {
        sha256_transform(state, buffer);
        memset(buffer, 0, SHA256_BLOCK_SIZE);
    }

    uint64_t bit_length = length * 8;
    memcpy(buffer + SHA256_BLOCK_SIZE - 8, &bit_length, 8);
    sha256_transform(state, buffer);

    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = state[i] & 0xff;
    }
}

int main() {
    const size_t num_hashes = 1UL << 24; // 2^32 hashes
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint32_t state[8];

    sha256_init(state);

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < num_hashes; ++i) {
        sha256_final(state, reinterpret_cast<const uint8_t*>(&i), sizeof(i), hash);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Calculated " << num_hashes << " hashes in " 
              << elapsed.count() << " seconds." << std::endl;

    return 0;
}
