#include <cuco/static_map.cuh>
#include <thrust/device_vector.h>
#include <thrust/host_vector.h>
#include <thrust/sequence.h>
#include <iostream>
#include <fstream>

// User-defined key type
struct custom_key_type {
    uint64_t hash;  // Use a 64-bit hash to fit within the 8-byte limit

    __host__ __device__ custom_key_type() : hash{0} {}

    __host__ __device__ custom_key_type(uint8_t const* data, size_t size) {
        hash = 0;
        for (size_t i = 0; i < size; ++i) {
            hash = hash * 31 + data[i]; // Simple hash function example
        }
    }

    __host__ __device__ bool operator==(const custom_key_type& other) const {
        return hash == other.hash;
    }
};

// User-defined value type
struct custom_value_type {
    uint64_t hash;  // Use a 64-bit hash to fit within the 8-byte limit

    __host__ __device__ custom_value_type() : hash{0} {}

    __host__ __device__ custom_value_type(uint8_t const* data, size_t size) {
        hash = 0;
        for (size_t i = 0; i < size; ++i) {
            hash = hash * 31 + data[i]; // Simple hash function example
        }
    }
};

// User-defined device hash callable
struct custom_hash {
    __device__ uint32_t operator()(custom_key_type const& k) const noexcept {
        return static_cast<uint32_t>(k.hash); // Use lower 32 bits for hash
    }
};

// User-defined device key equal callable
struct custom_key_equal {
    __device__ bool operator()(custom_key_type const& lhs, custom_key_type const& rhs) const noexcept {
        return lhs.hash == rhs.hash;
    }
};

// Fix the hexToBytes function to maintain byte order
void hexToBytes(const char* hex, uint8_t* bytes) {
    for (int i = 0; i < strlen(hex)/2; i++) {
        sscanf(hex + i*2, "%2hhx", &bytes[i]);
    }
}

// Global kernel to iterate over keys and use the device function
template <typename Map, typename KeyIter, typename ValueIter>
__global__ void example_kernel(Map map_ref, KeyIter key_begin, ValueIter value_begin, std::size_t num_keys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_keys) {
        // Example operation: find a key and update its value
        auto result = map_ref.find(key_begin[idx]);
        if (result != map_ref.end()) {
            result->second = value_begin[idx]; // Update the value
        }
    }
}

int main() {
    uint8_t all_target_hashes[10][100][32]; // 10 salts, each with 100 hashes
    uint8_t all_target_salts[10][8];        // 10 unique salts

    std::ifstream infile("in.txt");
    if (!infile) {
        std::cerr << "Error: Unable to open file in.txt\n";
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

    // Set empty sentinels
    auto const empty_key_sentinel = custom_key_type{};
    auto const empty_value_sentinel = custom_value_type{};

    // Construct a map with 100,000 slots using the given empty key/value sentinels.
    auto h_map = cuco::static_map<custom_key_type, custom_value_type, custom_key_equal, custom_hash>{
        cuco::extent<std::size_t, 100'000>{},
        cuco::empty_key{empty_key_sentinel},
        cuco::empty_value{empty_value_sentinel},
        custom_key_equal{},
        cuco::linear_probing<1, custom_hash>{}
    };

    // Create device vector for 1000 pairs
    thrust::device_vector<cuco::pair<custom_key_type, custom_value_type>> d_pairs(1000);

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 100; j++) {
            uint8_t data[32];
            for (int k = 0; k < 32; ++k) {
                data[k] = all_target_hashes[i][j][k];
            }
            d_pairs[i * 100 + j] = cuco::pair{custom_key_type(data, 32), custom_value_type(data, 32)};
        }
    }

    // Insert all 1000 pairs
    h_map.insert(d_pairs.begin(), d_pairs.end());

    // Prepare to find the key associated with the value 55
    uint8_t search_data[32];
    for (int j = 0; j < 32; ++j) {
        search_data[j] = all_target_hashes[6][88][j]; // Fill with the byte value 55
    }
    thrust::device_vector<custom_key_type> search_keys(1, custom_key_type(search_data, 32));
    thrust::device_vector<custom_value_type> found_values(1, empty_value_sentinel);

    // Get a reference for device operations
    auto map_ref = h_map.ref();

    // Define grid and block dimensions
    int threads_per_block = 256;
    int num_keys = search_keys.size();
    int num_blocks = (num_keys + threads_per_block - 1) / threads_per_block;

    // Launch the kernel
    example_kernel<<<num_blocks, threads_per_block>>>(map_ref, search_keys.begin(), found_values.begin(), num_keys);

    // Copy results back to host if needed
    thrust::host_vector<custom_value_type> h_values = found_values;

    // Output results or perform further processing
    for (std::size_t i = 0; i < search_keys.size(); ++i) {
        std::cout << "Key: " << search_keys[i].hash << ", Value: " << h_values[i].hash << std::endl;
    }

    return 0;
}
