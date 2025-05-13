#include <iostream>
#include <cstdio>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>

const int password_length = 7;
__device__ __constant__ char charset_global[] = "abcdefghijklmnopqrstuvwxyz0123456789";
const int charset_size = sizeof("abcdefghijklmnopqrstuvwxyz0123456789") - 1;

// Device funkcija za poređenje stringova
__device__ bool compareStrings(const char* a, const char* b, int length) {
    for (int i = 0; i < length; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// Brute-force CUDA kernel sa optimizacijom
__global__ void bruteForceKernel(char* target, char* result, long long offset, long long batchSize) {
    __shared__ char charset[charset_size]; // Shared memorija (brža)
    if (threadIdx.x < charset_size) {
        charset[threadIdx.x] = charset_global[threadIdx.x];
    }
    __syncthreads();

    long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batchSize) return;

    long long globalIdx = offset + idx;
    long long temp = globalIdx;
    char attempt[password_length + 1] = { 0 };

    // Unrolled dekodiranje broja u lozinku
    attempt[0] = charset[temp % charset_size]; temp /= charset_size;
    attempt[1] = charset[temp % charset_size]; temp /= charset_size;
    attempt[2] = charset[temp % charset_size]; temp /= charset_size;
    attempt[3] = charset[temp % charset_size]; temp /= charset_size;
    attempt[4] = charset[temp % charset_size]; temp /= charset_size;
    attempt[5] = charset[temp % charset_size]; temp /= charset_size;
    attempt[6] = charset[temp % charset_size];

    if (compareStrings(attempt, target, password_length)) {
        printf("Password found: %s (index %lld)\n", attempt, globalIdx);
        for (int i = 0; i < password_length; ++i)
            result[i] = attempt[i];
    }
}

int main() {
    char target[] = "abn1238";  // postavi ovdje lozinku koju tražiš
    char* d_target, * d_result;
    char result[password_length + 1] = { 0 };

    // Izračunaj ukupan broj kombinacija (koristi long long!)
    long long totalCombinations = 1;
    for (int i = 0; i < password_length; ++i)
        totalCombinations *= charset_size;

    // Alokacija
    cudaMalloc(&d_target, password_length + 1);
    cudaMalloc(&d_result, password_length + 1);
    cudaMemcpy(d_target, target, password_length + 1, cudaMemcpyHostToDevice);

    // Mjerenje vremena
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    // Kernel konfiguracija
    long long batchSize = 200000000;  // 200M pokušaja po kernelu
    int threadsPerBlock = 256;
    long long offset = 0;

    while (offset < totalCombinations) {
        long long currentBatch = std::min(batchSize, totalCombinations - offset);
        int numThreads = static_cast<int>(currentBatch);
        int numBlocks = (numThreads + threadsPerBlock - 1) / threadsPerBlock;

        bruteForceKernel << <numBlocks, threadsPerBlock >> > (d_target, d_result, offset, currentBatch);
        cudaDeviceSynchronize();

        // Provjeri da li je pronađena lozinka
        cudaMemcpy(result, d_result, password_length + 1, cudaMemcpyDeviceToHost);
        if (result[0] != '\0') break;

        offset += currentBatch;
        std::cout << "Checked up to index: " << offset << "\r";
    }

    // Završetak mjerenja
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);

    // Ispis rezultata
    if (result[0] != '\0') {
        std::cout << "\nPassword successfully cracked: " << result << std::endl;
    }
    else {
        std::cout << "\nPassword NOT found.\n";
    }

    std::cout << "Time taken for brute force: " << elapsedTime << " ms\n";

    // Čišćenje
    cudaFree(d_target);
    cudaFree(d_result);
    return 0;
}
