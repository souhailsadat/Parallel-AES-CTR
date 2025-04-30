# AES-CTR Parallel Implementation Project

## Overview
This project implements and compares sequential, OpenMP (shared memory), and CUDA (GPU) versions of the AES-CTR encryption algorithm. The goal is to analyze performance gains from parallelization across different key sizes (128/192/256-bit) and data sizes (100MB/500MB).

## Key Features
- **Three implementations**:
  - `SEQ_AES.c`: Sequential baseline
  - `OpenMP_AES.c`: Multi-threaded CPU (2-16 threads)
  - `CUDA_AES.c`: GPU-accelerated (Nvidia)
- **AES-CTR mode**: Parallel-friendly counter mode encryption
- **Performance metrics**: Timed execution for comparisons

## Key Findings
- Small files (5-10MB): OpenMP fastest
- Medium files (50-100MB): OpenMP (few threads) < CUDA (many threads)
- Large files (512MB): CUDA 10s vs OpenMP 25s vs Sequential 70s
