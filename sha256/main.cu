#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cuda_fp16.h>
#include <omp.h>

#define MAX_FOUND 1000
#define NUM_STREAMS 10  // One stream per salt

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"


__constant__ const unsigned long long total_passwords = 62ULL * 62 * 62 * 62 * 62 * 62;
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
__constant__ double reciprocal = 1.0 / 62.0;
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void sha256(const uint8_t* __restrict__ data, uint8_t* __restrict__ hash) {
    register uint32_t a = 0x6a09e667;
    register uint32_t b = 0xbb67ae85;
    register uint32_t c = 0x3c6ef372;
    register uint32_t d = 0xa54ff53a;
    register uint32_t e = 0x510e527f;
    register uint32_t f = 0x9b05688c;
    register uint32_t g = 0x1f83d9ab;
    register uint32_t h = 0x5be0cd19;

    __align__(4) uint32_t W[64];
   // Load the first 16 words (unrolled for potential speedup)
    W[0]  = ((uint32_t)data[0]  << 24) | ((uint32_t)data[1]  << 16) | ((uint32_t)data[2]  << 8) | data[3];
    W[1]  = ((uint32_t)data[4]  << 24) | ((uint32_t)data[5]  << 16) | ((uint32_t)data[6]  << 8) | data[7];
    W[2]  = ((uint32_t)data[8]  << 24) | ((uint32_t)data[9]  << 16) | ((uint32_t)data[10] << 8) | data[11];
    W[3]  = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) | 0x8000; // Padding starts here
    W[4]  = 0;
    W[5]  = 0;
    W[6]  = 0;
    W[7]  = 0;
    W[8]  = 0;
    W[9]  = 0;
    W[10] = 0;
    W[11] = 0;
    W[12] = 0;
    W[13] = 0;
    W[14] = 0;
    W[15] = 112; // Message length (64 bytes * 8 bits/byte = 512 bits)

    // Message schedule expansion (unrolled with reduced dependencies)
    #pragma unroll 48
    for (int i = 16; i < 64; i += 4) {
        uint32_t s0_1 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1_1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0_1 + W[i - 7] + s1_1;

        uint32_t s0_2 = rotr(W[i - 14], 7) ^ rotr(W[i - 14], 18) ^ (W[i - 14] >> 3);
        uint32_t s1_2 = rotr(W[i - 1], 17) ^ rotr(W[i - 1], 19) ^ (W[i - 1] >> 10);
        W[i + 1] = W[i - 15] + s0_2 + W[i - 6] + s1_2;

        uint32_t s0_3 = rotr(W[i - 13], 7) ^ rotr(W[i - 13], 18) ^ (W[i - 13] >> 3);
        uint32_t s1_3 = rotr(W[i], 17) ^ rotr(W[i], 19) ^ (W[i] >> 10);
        W[i + 2] = W[i - 14] + s0_3 + W[i - 5] + s1_3;

        uint32_t s0_4 = rotr(W[i - 12], 7) ^ rotr(W[i - 12], 18) ^ (W[i - 12] >> 3);
        uint32_t s1_4 = rotr(W[i + 1], 17) ^ rotr(W[i + 1], 19) ^ (W[i + 1] >> 10);
        W[i + 3] = W[i - 13] + s0_4 + W[i - 4] + s1_4;
    }

    #pragma unroll 64
    for (int i = 0; i < 64; i += 4) {
        // Round i
        uint32_t S1_1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch_1 = (e & f) ^ (~e & g);
        uint32_t temp1_1 = h + S1_1 + ch_1 + K[i] + W[i];
        uint32_t S0_1 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj_1 = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2_1 = S0_1 + maj_1;
    
        h = g;
        g = f;
        f = e;
        e = d + temp1_1;
        d = c;
        c = b;
        b = a;
        a = temp1_1 + temp2_1;
    
        // Round i + 1
        uint32_t S1_2 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch_2 = (e & f) ^ (~e & g);
        uint32_t temp1_2 = h + S1_2 + ch_2 + K[i + 1] + W[i + 1];
        uint32_t S0_2 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj_2 = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2_2 = S0_2 + maj_2;
    
        h = g;
        g = f;
        f = e;
        e = d + temp1_2;
        d = c;
        c = b;
        b = a;
        a = temp1_2 + temp2_2;
    
        // Round i + 2
        uint32_t S1_3 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch_3 = (e & f) ^ (~e & g);
        uint32_t temp1_3 = h + S1_3 + ch_3 + K[i + 2] + W[i + 2];
        uint32_t S0_3 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj_3 = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2_3 = S0_3 + maj_3;
    
        h = g;
        g = f;
        f = e;
        e = d + temp1_3;
        d = c;
        c = b;
        b = a;
        a = temp1_3 + temp2_3;
    
        // Round i + 3
        uint32_t S1_4 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch_4 = (e & f) ^ (~e & g);
        uint32_t temp1_4 = h + S1_4 + ch_4 + K[i + 3] + W[i + 3];
        uint32_t S0_4 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj_4 = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2_4 = S0_4 + maj_4;
    
        h = g;
        g = f;
        f = e;
        e = d + temp1_4;
        d = c;
        c = b;
        b = a;
        a = temp1_4 + temp2_4;
    }

    // Add the compressed chunk to the current hash value
    a += 0x6a09e667;
    b += 0xbb67ae85;
    c += 0x3c6ef372;
    d += 0xa54ff53a;
    e += 0x510e527f;
    f += 0x9b05688c;
    g += 0x1f83d9ab;
    h += 0x5be0cd19;
    
    hash[0] = a >> 24;
    hash[1] = a >> 16;
    hash[2] = a >> 8;
    hash[3] = a;

    hash[4] = b >> 24;
    hash[5] = b >> 16;
    hash[6] = b >> 8;
    hash[7] = b;

    hash[8] = c >> 24;
    hash[9] = c >> 16;
    hash[10] = c >> 8;
    hash[11] = c;

    hash[12] = d >> 24;
    hash[13] = d >> 16;
    hash[14] = d >> 8;
    hash[15] = d;

    hash[16] = e >> 24;
    hash[17] = e >> 16;
    hash[18] = e >> 8;
    hash[19] = e;

    hash[20] = f >> 24;
    hash[21] = f >> 16;
    hash[22] = f >> 8;
    hash[23] = f;

    hash[24] = g >> 24;
    hash[25] = g >> 16;
    hash[26] = g >> 8;
    hash[27] = g;

    hash[28] = h >> 24;
    hash[29] = h >> 16;
    hash[30] = h >> 8;
    hash[31] = h;
}


// Fix the hexToBytes function to maintain byte order
void hexToBytes(const char* hex, uint8_t* bytes) {
    for (int i = 0; i < strlen(hex)/2; i++) {
        sscanf(hex + i*2, "%2hhx", &bytes[i]);
    }
}

int f(const uint8_t* data, int length) {
    unsigned int hash = 0;
    for (int i = 0; i < length; ++i) {
        hash = (hash << 5) - hash + data[i];
    }
    return hash % 799997;
}

__device__ int f2(const uint8_t* __restrict__ data, int length) {
    unsigned int hash = 0;
    for (int i = 0; i < length; ++i) {
        hash = (hash << 5) - hash + data[i];
    }
    return hash % 799997;
}

// Node structure for AVL Tree
struct AVLNode {
    uint8_t hash[32];
    AVLNode* left;
    AVLNode* right;
    int height;
};

// Function to create a new AVL node
AVLNode* createNode(const uint8_t* hash) {
    AVLNode* node = new AVLNode();
    std::copy(hash, hash + 32, node->hash);
    node->left = node->right = nullptr;
    node->height = 1; // Initial height of a new node is 1
    return node;
}

// Function to get the height of the tree
int height(AVLNode* node) {
    return node ? node->height : 0;
}

// Function to get the balance factor of a node
int getBalance(AVLNode* node) {
    return node ? height(node->left) - height(node->right) : 0;
}

// Right rotate the subtree rooted with y
AVLNode* rightRotate(AVLNode* y) {
    AVLNode* x = y->left;
    AVLNode* T2 = x->right;

    // Perform rotation
    x->right = y;
    y->left = T2;

    // Update heights
    y->height = std::max(height(y->left), height(y->right)) + 1;
    x->height = std::max(height(x->left), height(x->right)) + 1;

    // Return new root
    return x;
}

// Left rotate the subtree rooted with x
AVLNode* leftRotate(AVLNode* x) {
    AVLNode* y = x->right;
    AVLNode* T2 = y->left;

    // Perform rotation
    y->left = x;
    x->right = T2;

    // Update heights
    x->height = std::max(height(x->left), height(x->right)) + 1;
    y->height = std::max(height(y->left), height(y->right)) + 1;

    // Return new root
    return y;
}

// AVL tree insertion logic
AVLNode* insert(AVLNode* node, const uint8_t* hash) {
    if (!node) return createNode(hash);

    if (std::lexicographical_compare(hash, hash + 32, node->hash, node->hash + 32)) {
        node->left = insert(node->left, hash);
    } else if (std::lexicographical_compare(node->hash, node->hash + 32, hash, hash + 32)) {
        node->right = insert(node->right, hash);
    } else {
        return node; // Duplicate hashes are not allowed
    }

    // Update height and balance the tree
    node->height = 1 + std::max(height(node->left), height(node->right));
    int balance = getBalance(node);

    // Perform rotations if necessary
    if (balance > 1 && std::lexicographical_compare(hash, hash + 32, node->left->hash, node->left->hash + 32)) {
        return rightRotate(node);
    }
    if (balance < -1 && std::lexicographical_compare(node->right->hash, node->right->hash + 32, hash, hash + 32)) {
        return leftRotate(node);
    }
    if (balance > 1 && std::lexicographical_compare(node->left->hash, node->left->hash + 32, hash, hash + 32)) {
        node->left = leftRotate(node->left);
        return rightRotate(node);
    }
    if (balance < -1 && std::lexicographical_compare(hash, hash + 32, node->right->hash, node->right->hash + 32)) {
        node->right = rightRotate(node->right);
        return leftRotate(node);
    }

    return node;
}

// In-order traversal to flatten the AVL tree
void inOrderTraversal(AVLNode* node, std::vector<std::vector<uint8_t>>& sortedHashes) {
    if (node) {
        inOrderTraversal(node->left, sortedHashes);
        sortedHashes.push_back(std::vector<uint8_t>(node->hash, node->hash + 32));
        inOrderTraversal(node->right, sortedHashes);
    }
}

// Function to insert hashes into the AVL tree
AVLNode* insertHashesIntoAVLTree(uint8_t all_target_hashes[10][100][32]) {
    AVLNode* root = nullptr;

    for (int salt_index = 0; salt_index < 10; salt_index++) {
        for (int hash_index = 0; hash_index < 100; hash_index++) {
            // Insert the hash into the AVL tree
            root = insert(root, all_target_hashes[salt_index][hash_index]);
        }
    }

    return root;
}

__device__ int compareHashes(const uint8_t* hash1, const uint8_t* hash2) {
    for (int i = 0; i < 32; ++i) {
        if (hash1[i] < hash2[i]) return -1;
        if (hash1[i] > hash2[i]) return 1;
    }
    return 0;
}

__device__ bool binarySearchHashes(
    const uint8_t* sortedHashes, 
    int num_hashes, 
    const uint8_t* targetHash, 
    const int* shared_first_letter_index
) {
    // Extract the first 4 bits of the target hash
    uint8_t firstLetter = targetHash[0] >> 4;
    
    // Use the first letter index to potentially reduce search space
    int start_index = (firstLetter < 16) ? shared_first_letter_index[firstLetter] : 0;
    int end_index = (firstLetter + 1 < 16 && shared_first_letter_index[firstLetter + 1] != -1) 
                    ? shared_first_letter_index[firstLetter + 1] 
                    : num_hashes;
    // int start_index = 0;
    // int end_index = num_hashes;
    int left = start_index;
    int right = end_index - 1;

    while (left <= right) {
        int mid = left + ((right - left) >> 1);

        const uint8_t* midHash = &sortedHashes[mid * 32];
        int cmp = compareHashes(targetHash, midHash);

        if (cmp == 0) {
            return true; // Match found
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return false; // No match found
}

struct FoundPassword {
    char password[7];
    uint8_t hash[32];
    uint8_t salt[8];
};


__global__ void find_passwords_optimized_multi(
    const uint8_t* __restrict__ target_salts,
    const uint8_t* __restrict__ target_hashes,
    const uint8_t* __restrict__ sortedHashes,
    int* __restrict__ num_found,
    FoundPassword* __restrict__ found_passwords,
    const int* __restrict__ d_hash_data,
    const int* __restrict__ d_first_letter_index,
    int salt_index
) {
    // Shared memory declaration
    __shared__ uint8_t shared_salts[8];
    __shared__ int shared_first_letter_index[16];

    // Load data into shared memory
    if (threadIdx.x < 8) {
        shared_salts[threadIdx.x] = target_salts[threadIdx.x];
    }
    if (threadIdx.x < 16) {
        shared_first_letter_index[threadIdx.x] = d_first_letter_index[threadIdx.x];
    }
    __syncthreads();

    // Use shared memory in computations
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    for (uint64_t password_idx = tid; password_idx < total_passwords; password_idx += 1572864) {
        uint64_t idx = password_idx;
        uint8_t combined[14] __attribute__((aligned(16)));

        #pragma unroll
        for (int i = 0; i < 6; ++i) {
            combined[i] = charset[idx % 62];
            combined[6 + i] = shared_salts[i];
            idx = static_cast<uint64_t>(idx * reciprocal);
        }
        
        combined[12] = shared_salts[6];
        combined[13] = shared_salts[7];
        uint8_t hash[32] __attribute__((aligned(32)));
        sha256(combined, hash);
        int index = f2(hash, 4);

        while (d_hash_data[index] != -1) {
            if (binarySearchHashes(sortedHashes, 100, hash, shared_first_letter_index)) {
                atomicAdd(num_found, 1);
                break;
            }
            index += 1;
        }
    }
}



// Function to create sorted hashes for each salt
std::vector<std::vector<std::vector<uint8_t>>> createSaltSpecificSortedHashes(uint8_t all_target_hashes[10][100][32]) {
    std::vector<std::vector<std::vector<uint8_t>>> saltSpecificSortedHashes(10);

    for (int salt_index = 0; salt_index < 10; salt_index++) {
        // Create an AVL tree for this salt's hashes
        AVLNode* root = nullptr;

        // Insert hashes for this salt into the AVL tree
        for (int hash_index = 0; hash_index < 100; hash_index++) {
            root = insert(root, all_target_hashes[salt_index][hash_index]);
        }

        // Flatten the AVL tree into a sorted array
        std::vector<std::vector<uint8_t>> sortedHashesForSalt;
        inOrderTraversal(root, sortedHashesForSalt);

        saltSpecificSortedHashes[salt_index] = sortedHashesForSalt;
    }

    return saltSpecificSortedHashes;
}


int main() {
    uint8_t all_target_hashes[10][100][32]; // 10 salts, each with 100 hashes
    uint8_t all_target_salts[10][8];        // 10 unique salts
    cudaStream_t streams[NUM_STREAMS];

    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaStreamCreate(&streams[i]);
    }

    std::ifstream infile("in.txt");
    if (!infile) {
        printf("Error: Unable to open file in.txt\n");
        return 1;
    }

    std::string line;
    int salt_index = 0;
    int hash_index = 0;

    while (std::getline(infile, line) && salt_index < 10) {
        hexToBytes(line.substr(0, 64).c_str(), all_target_hashes[salt_index][hash_index]);

        if (hash_index == 0) {
            hexToBytes(line.substr(65, 16).c_str(), all_target_salts[salt_index]);
        }

        hash_index++;
        if (hash_index >= 100) {
            hash_index = 0;
            salt_index++;
        }
    }

    // Create sorted hashes for each salt
    auto saltSpecificSortedHashes = createSaltSpecificSortedHashes(all_target_hashes);

    // After creating saltSpecificSortedHashes
    std::vector<std::vector<int>> firstLetterIndex(10, std::vector<int>(16, -1));

    for (int salt_index = 0; salt_index < 10; salt_index++) {
        for (int i = 0; i < saltSpecificSortedHashes[salt_index].size(); i++) {
            // Get the first hex character (first 4 bits)
            uint8_t firstLetter = saltSpecificSortedHashes[salt_index][i][0] >> 4;
            
            // Set the index if it's not already set
            if (firstLetterIndex[salt_index][firstLetter] == -1) {
                firstLetterIndex[salt_index][firstLetter] = i;
            }
        }
    }


    const int HASH_TABLE_SIZE = 799997; // Adjusted to accommodate 1000 target hashes

    std::vector<std::vector<int>> hash_data_streams(NUM_STREAMS);
    #pragma omp parallel for
    for (int salt_index = 0; salt_index < NUM_STREAMS; salt_index++) {
        // Create a hash table for each salt's 100 hashes
        hash_data_streams[salt_index].resize(HASH_TABLE_SIZE, -1);
    
        for (int hash_index = 0; hash_index < 100; hash_index++) {
            // Calculate the hash value for the current hash
            int index = f(all_target_hashes[salt_index][hash_index], 4);
    
            // Use linear probing to resolve collisions
            while (hash_data_streams[salt_index][index] != -1) {
                index = (index + 1) % HASH_TABLE_SIZE;
            }
    
            // Store the index of the hash in the hash table
            hash_data_streams[salt_index][index] = hash_index;
        }
    }

    // Declare device pointers
    uint8_t* d_target_salts_streams[NUM_STREAMS];
    uint8_t* d_target_hashes_streams[NUM_STREAMS];
    int* d_hash_data_streams[NUM_STREAMS];
    uint8_t* d_sorted_hashes_streams[NUM_STREAMS];
    int* d_num_found_streams[NUM_STREAMS];
    int* d_first_letter_index_streams[NUM_STREAMS];
    FoundPassword* d_found_passwords_streams[NUM_STREAMS];

    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaMalloc(&d_target_salts_streams[i], 8 * sizeof(uint8_t));
        cudaMalloc(&d_target_hashes_streams[i], 100 * 32 * sizeof(uint8_t));
        cudaMalloc(&d_hash_data_streams[i], HASH_TABLE_SIZE * sizeof(int));
        cudaMalloc(&d_sorted_hashes_streams[i], 100 * 32 * sizeof(uint8_t));
        cudaMalloc(&d_num_found_streams[i], sizeof(int));
        cudaMalloc(&d_found_passwords_streams[i], 100 * sizeof(FoundPassword));
        cudaMalloc(&d_first_letter_index_streams[i], 16 * sizeof(int));

        // Copy specific salt for this stream
        cudaMemcpyAsync(d_target_salts_streams[i], 
                        all_target_salts[i], 
                        8 * sizeof(uint8_t), 
                        cudaMemcpyHostToDevice, 
                        streams[i]);

        // Copy specific hashes for this salt
        cudaMemcpyAsync(d_target_hashes_streams[i], 
                        all_target_hashes[i], 
                        100 * 32 * sizeof(uint8_t), 
                        cudaMemcpyHostToDevice, 
                        streams[i]);

        // Copy hash data
        cudaMemcpyAsync(d_hash_data_streams[i], 
                        hash_data_streams[i].data(), 
                        HASH_TABLE_SIZE * sizeof(int), 
                        cudaMemcpyHostToDevice, 
                        streams[i]);
                        
        for (size_t j = 0; j < saltSpecificSortedHashes[i].size(); ++j) {
            cudaMemcpyAsync(d_sorted_hashes_streams[i] + j * 32,
                            saltSpecificSortedHashes[i][j].data(),
                            32 * sizeof(uint8_t),
                            cudaMemcpyHostToDevice,
                            streams[i]);
        }

        // Copy first letter indices to device
        cudaMemcpyAsync(
            d_first_letter_index_streams[i], 
            firstLetterIndex[i].data(), 
            16 * sizeof(int), 
            cudaMemcpyHostToDevice, 
            streams[i]
        );

        // Initialize found passwords counter to zero
        cudaMemsetAsync(d_num_found_streams[i], 0, sizeof(int), streams[i]);
    }

    // Determine the number of threads per block
    int blockSize = 512; // Choose a block size that is a multiple of the warp size

    // Calculate the total number of threads needed
    uint64_t totalThreads = total_passwords;

    // Calculate the number of blocks needed to cover all threads
    int numBlocks = (totalThreads + blockSize - 1) / blockSize;

    // Ensure the number of blocks does not exceed the maximum allowed by the device
    numBlocks = 3072;

    // printf("Kernel configuration:\n");
    // printf("- Block size: %d\n", blockSize);
    // printf("- Number of blocks: %d\n", numBlocks);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    cudaEventRecord(start);

    // Launch kernels on different streams
    #pragma unroll
    for (int i = 0; i < 10; ++i) {
        find_passwords_optimized_multi<<<numBlocks, blockSize, 0, streams[i]>>>(
            d_target_salts_streams[i],       // Device pointer to the specific salt
            d_target_hashes_streams[i],      // Device pointer to the specific hashes
            d_sorted_hashes_streams[i],      // Device pointer to the specific sorted hashes
            d_num_found_streams[i],          // Device pointer to store the number of found passwords
            d_found_passwords_streams[i],
            d_hash_data_streams[i],          // Device pointer to the specific hash data
            d_first_letter_index_streams[i], // Device pointer to first letter indices
            i                                // Salt index
        );
    }

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA Error: %s\n", cudaGetErrorString(err));
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float gpu_time_ms;
    cudaEventElapsedTime(&gpu_time_ms, start, stop);
    
    printf(BOLD CYAN "\nPerformance Metrics:\n" RESET);
    printf(YELLOW "GPU Time: " RESET "%.2f ms\n", gpu_time_ms);
    
    int h_num_found = 0;

    // Aggregate results from all streams
    for (int i = 0; i < NUM_STREAMS; ++i) {
        int stream_found = 0;
        cudaMemcpyAsync(&stream_found, d_num_found_streams[i], sizeof(int), cudaMemcpyDeviceToHost, streams[i]);
        h_num_found += stream_found;
    }
    
    // Synchronize all streams to ensure memory copy is complete
    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaStreamSynchronize(streams[i]);
    }
    
    printf("Number of found passwords: %d\n", h_num_found);
    
    // // Allocate memory on the host to store found passwords
    // FoundPassword* h_found_passwords = new FoundPassword[MAX_FOUND];

    // // Copy the found passwords from device to host
    // cudaMemcpy(h_found_passwords, d_found_passwords, h_num_found * sizeof(FoundPassword), cudaMemcpyDeviceToHost);

    // // Iterate over the found passwords and print their details
    // // for (int i = 0; i < h_num_found; i++) {
    // //     const FoundPassword& fp = h_found_passwords[i];
        
    // //     // Print the hash
    // //     for (int j = 0; j < 32; j++) {
    // //         printf("%02x", fp.hash[j]);
    // //     }
    // //     printf(":");
        
    // //     // Print the salt
    // //     for (int j = 0; j < 8; j++) {
    // //         printf("%02x", fp.salt[j]);
    // //     }
    // //     printf(":%s\n", fp.password);
    // // }

    // Cleanup streams and memory
    for (int i = 0; i < NUM_STREAMS; ++i) {
        cudaFree(d_target_salts_streams[i]);
        cudaFree(d_target_hashes_streams[i]);
        cudaFree(d_hash_data_streams[i]);
        cudaFree(d_sorted_hashes_streams[i]);
        cudaFree(d_num_found_streams[i]);
        cudaFree(d_found_passwords_streams[i]);
        cudaFree(d_first_letter_index_streams[i]);
        
        // Destroy the stream
        cudaStreamDestroy(streams[i]);
    }
    return 0;
}