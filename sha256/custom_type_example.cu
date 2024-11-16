#include <cuco/static_map.cuh>
#include <thrust/device_vector.h>
#include <thrust/host_vector.h>
#include <thrust/iterator/counting_iterator.h>
#include <thrust/iterator/transform_iterator.h>
#include <thrust/logical.h>
#include <thrust/transform.h>
#include <iostream>

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

int main(void) {
    constexpr std::size_t num_pairs = 80'000;

    // Set empty sentinels
    auto const empty_key_sentinel = custom_key_type{};
    auto const empty_value_sentinel = custom_value_type{};

    // Create an iterator of input key/value pairs
    auto pairs_begin = thrust::make_transform_iterator(
        thrust::make_counting_iterator<int32_t>(0),
        cuda::proclaim_return_type<cuco::pair<custom_key_type, custom_value_type>>(
            [] __device__(auto i) {
                uint8_t data[32];
                for (int j = 0; j < 32; ++j) {
                    data[j] = static_cast<uint8_t>(i & 0xFF); // Example initialization
                }
                return cuco::pair{custom_key_type(data, 32), custom_value_type(data, 32)};
            }));

    // Construct a map with 100,000 slots using the given empty key/value sentinels.
    auto map = cuco::static_map{cuco::extent<std::size_t, 100'000>{},
                                cuco::empty_key{empty_key_sentinel},
                                cuco::empty_value{empty_value_sentinel},
                                custom_key_equal{},
                                cuco::linear_probing<1, custom_hash>{}};

    // Inserts 80,000 pairs into the map
    map.insert(pairs_begin, pairs_begin + num_pairs);

    // Prepare to find the key associated with the value 55
    uint8_t search_data[32];
    for (int j = 0; j < 32; ++j) {
        search_data[j] = 55; // Fill with the byte value 55
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
        std::cout << "Found key with value 55: (" << host_key.hash << ")\n";
    } else {
        std::cout << "Key with value 55 not found.\n";
    }

    return 0;
}
