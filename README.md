# HashXtreme

**HashXtreme** is a high-performance hashing tool designed to leverage the power of NVIDIA GPUs for accelerated computation of hashing algorithms, specifically optimized for SHA-256. With advanced techniques in parallel processing and memory optimization, HashXtreme aims to deliver unmatched speed and efficiency.

## Architecture

- **GPU Parallel Processing**: Utilizes NVIDIA GPUs for enhanced performance.
- **Multi-Stream Execution**: Implements 4 CUDA streams for concurrent processing.
- **Shared Memory Optimization**: Efficient storage for hashes and salts.
- **Vectorized Operations**: Enables rapid password generation.

## Technical Specifications

- **Password Space**: Supports a vast password space of \(62^6\) combinations (56,800,235,584 possibilities).
- **Batch Processing**: Configurable batch size for efficient processing.
- **Dynamic Configuration**: Adjusts block and thread configurations based on GPU capabilities.
- **Optimized Memory Transfers**: Utilizes pinned memory for faster data transfer rates.

## Core Components

- **Custom SHA-256 Implementation**: Tailored specifically to handle a 14-byte input consisting of both password and salt, optimizing the hashing process for enhanced security and performance.
- **Efficient Password Generation**:  Leverages bit manipulation techniques to generate passwords quickly.
- **Parallel Hash Comparison**: Utilizes vector operations for fast comparisons of hashed values.
- **Progress Tracking**: Real-time reporting of progress and performance metrics.

## Input/Output

- **Input**: Reads `hash:salt` pairs from `in.txt`.
- **Multiple Combinations**: Supports up to 100 hash-salt combinations.
- **Real-Time Reporting**: Provides ongoing updates on processing progress.
- **Performance Metrics**: Displays performance in GH/s (Giga Hashes per second).

## Optimizations

- **Coalesced Memory Access Patterns**: Enhances memory access efficiency.
- **Unrolled Loops**: Improves instruction throughput for better performance.
- **Shared Memory Usage**: Optimizes frequently accessed data storage.
- **PTX Assembly**: Utilizes optimized vector operations for enhanced speed.
