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
    int32_t a;
    int32_t b;

    __host__ __device__ custom_key_type() {}
    __host__ __device__ custom_key_type(int32_t x) : a{x}, b{x} {}
};

// User-defined value type
struct custom_value_type {
    int32_t f;
    int32_t s;

    __host__ __device__ custom_value_type() {}
    __host__ __device__ custom_value_type(int32_t x) : f{x}, s{x} {}
};

// User-defined device hash callable
struct custom_hash {
    __device__ uint32_t operator()(custom_key_type const& k) const noexcept { return k.a; }
};

// User-defined device key equal callable
struct custom_key_equal {
    __device__ bool operator()(custom_key_type const& lhs, custom_key_type const& rhs) const noexcept {
        return lhs.a == rhs.a;
    }
};

int main(void) {
    constexpr std::size_t num_pairs = 80'000;

    // Set empty sentinels
    auto const empty_key_sentinel = custom_key_type{-1};
    auto const empty_value_sentinel = custom_value_type{-1};

    // Create an iterator of input key/value pairs
    auto pairs_begin = thrust::make_transform_iterator(
        thrust::make_counting_iterator<int32_t>(0),
        cuda::proclaim_return_type<cuco::pair<custom_key_type, custom_value_type>>(
            [] __device__(auto i) { return cuco::pair{custom_key_type{i}, custom_value_type{i}}; }));

    // Construct a map with 100,000 slots using the given empty key/value sentinels.
    auto map = cuco::static_map{cuco::extent<std::size_t, 100'000>{},
                                cuco::empty_key{empty_key_sentinel},
                                cuco::empty_value{empty_value_sentinel},
                                custom_key_equal{},
                                cuco::linear_probing<1, custom_hash>{}};

    // Inserts 80,000 pairs into the map
    map.insert(pairs_begin, pairs_begin + num_pairs);

    // Prepare to find the key associated with the value 55
    thrust::device_vector<custom_key_type> search_keys(1, custom_key_type{55});
    thrust::device_vector<custom_value_type> found_values(1, empty_value_sentinel);

    // Use the find method to locate the key-value pair
    map.find(search_keys.begin(), search_keys.end(), found_values.begin());

    // Copy the found key from device to host
    custom_key_type host_key = search_keys[0];
    custom_value_type host_value = found_values[0];

    // Check if the value was found
    if (host_value.f == 55) {
        std::cout << "Found key with value 55: (" << host_key.a << ", " << host_key.b << ")\n";
    } else {
        std::cout << "Key with value 55 not found.\n";
    }

    return 0;
}
