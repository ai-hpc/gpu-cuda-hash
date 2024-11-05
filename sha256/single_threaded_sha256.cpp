#include <iostream>
#include <openssl/evp.h>
#include <chrono>
#include <cmath> // Include cmath for std::pow

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

int main() {
    uint64_t max_idx = static_cast<uint64_t>(std::pow(62, 6)); // Correctly compute 62^6

    auto start = std::chrono::high_resolution_clock::now();

    for (uint64_t idx = 0; idx < max_idx; ++idx) {
        uint8_t password[6];
        generate_password(idx, password);
        std::string password_str(reinterpret_cast<char*>(password), 6);
        sha256(password_str);
        if(idx > 10000000)break;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;

    return 0;
}
