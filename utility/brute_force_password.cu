#include <iostream>
#include <chrono>
#include <cmath>

__global__ void generatePasswordsBatch(char *charset, int charsetSize, int passwordLength, char *results, unsigned long long startIdx, unsigned long long batchSize) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x + startIdx;

    if (idx < startIdx + batchSize) {
        unsigned long long tempIdx = idx;
        for (int i = 0; i < passwordLength; ++i) {
            results[(idx - startIdx) * passwordLength + i] = charset[tempIdx % charsetSize];
            tempIdx /= charsetSize;
        }
    }
}

int main() {
    const int charsetSize = 62;
    const int passwordLength = 6;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const unsigned long long totalPasswords = static_cast<unsigned long long>(pow(charsetSize, passwordLength));
    const unsigned long long batchSize = 1000000; // Example batch size

    char *d_charset, *d_results;
    cudaMalloc(&d_charset, charsetSize * sizeof(char));
    cudaMalloc(&d_results, batchSize * passwordLength * sizeof(char));
    cudaMemcpy(d_charset, charset, charsetSize * sizeof(char), cudaMemcpyHostToDevice);

    auto start = std::chrono::high_resolution_clock::now();

    for (unsigned long long startIdx = 0; startIdx < totalPasswords; startIdx += batchSize) {
        unsigned long long currentBatchSize = std::min(batchSize, totalPasswords - startIdx);
        generatePasswordsBatch<<<(currentBatchSize + 255) / 256, 256>>>(d_charset, charsetSize, passwordLength, d_results, startIdx, currentBatchSize);
        cudaDeviceSynchronize();
        // Process the generated passwords in d_results here
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    std::cout << "Batched Generation Time: " << diff.count() << " s\n";

    cudaFree(d_charset);
    cudaFree(d_results);
    return 0;
}
