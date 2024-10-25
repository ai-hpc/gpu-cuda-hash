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

- **Custom SHA-256 Implementation**: Tailored for optimal performance on GPU.
- **Efficient Password Generation**: Leverages bit manipulation techniques.
- **Parallel Hash Comparison**: Utilizes vector operations for quick comparisons.
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

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/secure-firmware/HashXtreme.git
   cd HashXtreme
   ```

2. Build the project:
   ```bash
   make
   ```

3. Prepare your `in.txt` file with `hash:salt` pairs.

4. Run the tool:
   ```bash
   ./hashxtreme in.txt
   ```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
