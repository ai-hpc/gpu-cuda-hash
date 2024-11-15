#include <cuco/static_map.cuh>
#include <thrust/host_vector.h>
#include <thrust/device_vector.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>

// Define a custom key type using a uint8_t array of size 32
struct CustomKey {
  std::array<uint8_t, 32> data;

  __host__ __device__ CustomKey() : data{} {}
  __host__ __device__ CustomKey(const std::array<uint8_t, 32>& arr) : data(arr) {}

  // Equality operator
  __host__ __device__ bool operator==(const CustomKey& other) const {
    for (size_t i = 0; i < 32; ++i) {
      if (data[i] != other.data[i]) {
        return false;
      }
    }
    return true;
  }
};

// Custom hash function for CustomKey
struct custom_key_hash {
  __device__ uint32_t operator()(CustomKey const& key) const noexcept {
    // Simple hash function example: sum of all bytes
    uint32_t hash = 0;
    for (auto byte : key.data) {
      hash = hash * 31 + byte;
    }
    return hash;
  }
};

// Custom equality function for CustomKey
struct custom_key_equal {
  __device__ bool operator()(CustomKey const& lhs, CustomKey const& rhs) const noexcept {
    return lhs == rhs;
  }
};

constexpr cuco::empty_key<CustomKey> empty_key_sentinel{CustomKey{{0xFF}}}; // Use a unique sentinel
constexpr cuco::empty_value<int> empty_value_sentinel{-1};

// Function to convert hex string to bytes
void hexToBytes(const char* hex, uint8_t* bytes) {
  for (size_t i = 0; i < 32; ++i) {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
}

int main() {
  // Create a static map using the custom key type
  cuco::static_map<CustomKey, int, custom_key_equal, custom_key_hash> map(
      1000,                      // Capacity
      empty_key_sentinel,        // Empty key sentinel
      empty_value_sentinel,      // Empty value sentinel
      custom_key_equal{},        // Key equality comparator
      cuco::linear_probing<4, custom_key_hash>{}, // Probing scheme
      cuco::cuda_allocator<cuco::pair<CustomKey, int>>{}, // Allocator
      cuco::storage{}            // Storage
  );

  // Example usage: insert and find
  CustomKey key1;
  hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", key1.data.data());
  map.insert(std::make_pair(key1, 42));

  int value;
  bool found = map.find(key1, value);

  if (found) {
    std::cout << "Key found with value: " << value << std::endl;
  } else {
    std::cout << "Key not found." << std::endl;
  }

  return 0;
}
