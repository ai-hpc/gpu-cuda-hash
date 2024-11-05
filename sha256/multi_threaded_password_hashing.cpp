#include <iostream>
#include <openssl/evp.h>
#include <chrono>
#include <thread>
#include <vector>
#include <cmath>

const char host_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

std::string sha256(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to initialize digest");
    }

    if (EVP_DigestUpdate(context, input.c_str(), input.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to update digest");
    }

    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(context);

    return std::string(reinterpret_cast<char*>(hash), lengthOfHash);
}

void generate_password(uint64_t idx, uint8_t password[6]) {
    for (int i = 0; i < 6; ++i) {
        password[i] = host_charset[idx % 62];
        idx /= 62;
    }
}

void hash_passwords(uint64_t start_idx, uint64_t end_idx) {
    for (uint64_t idx = start_idx; idx < end_idx; ++idx) {
        uint8_t password[6];
        generate_password(idx, password);
        std::string password_str(reinterpret_cast<char*>(password), 6);
        sha256(password_str);
    }
}

int main() {
    uint64_t max_idx = static_cast<uint64_t>(std::pow(20, 6)); // 62^6
    int num_threads = std::thread::hardware_concurrency();
    num_threads = std::max(10, std::min(num_threads, 20)); // Limit threads between 10 and 20

    std::vector<std::thread> threads;
    uint64_t range_per_thread = max_idx / num_threads;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; ++i) {
        uint64_t start_idx = i * range_per_thread;
        uint64_t end_idx = (i == num_threads - 1) ? max_idx : start_idx + range_per_thread;
        threads.emplace_back(hash_passwords, start_idx, end_idx);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;

    return 0;
}
