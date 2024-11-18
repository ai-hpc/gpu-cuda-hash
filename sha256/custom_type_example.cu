#include <cuco/static_map.cuh>
#include <thrust/device_vector.h>
#include <thrust/host_vector.h>
#include <thrust/iterator/counting_iterator.h>
#include <thrust/iterator/transform_iterator.h>
#include <thrust/logical.h>
#include <thrust/transform.h>
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

int main(void) {

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


      // Set empty sentinels
    auto const empty_key_sentinel = custom_key_type{};
    auto const empty_value_sentinel = custom_value_type{};

    // Construct a map with 100,000 slots using the given empty key/value sentinels.
    auto map = cuco::static_map{cuco::extent<std::size_t, 100'000>{},
                                cuco::empty_key{empty_key_sentinel},
                                cuco::empty_value{empty_value_sentinel},
                                custom_key_equal{},
                                cuco::linear_probing<1, custom_hash>{}};

    // Create device vector for 100 pairs
    thrust::device_vector<cuco::pair<custom_key_type, custom_value_type>> d_pairs(1000);

    // Initialize 100 pairs with values 1-100
    for (int i = 1; i <= 1000; i++) {
        uint8_t data[32];
        for (int j = 0; j < 32; ++j) {
            data[j] = static_cast<uint8_t>(i & 0xFF);
        }
        d_pairs[i-1] = cuco::pair{custom_key_type(data, 32), custom_value_type(data, 32)};
    }

    // Insert all 100 pairs
    map.insert(d_pairs.begin(), d_pairs.end());

    // Prepare to find the key associated with the value 55
    uint8_t search_data[32];
    for (int j = 0; j < 32; ++j) {
        search_data[j] = 222; // Fill with the byte value 55
    }
    thrust::device_vector<custom_key_type> search_keys(1, custom_key_type(search_data, 32));
    thrust::device_vector<custom_value_type> found_values(1, empty_value_sentinel);

    // Use the find method to locate the key-value pair
    map.find(search_keys.begin(), search_keys.end(), found_values.begin());

    // Copy the found key from device to host
    custom_key_type host_key = search_keys[0];
    custom_value_type host_value = found_values[0];

    // Check if the value was found
    if (host_value.hash == custom_value_type(search_data, 32).hash) {
        std::cout << "Found key with value 799: (" << host_key.hash << ")\n";
    } else {
        std::cout << "Key with value 799 not found.\n";
    }

    return 0;
}
