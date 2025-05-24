#include <iostream>
#include <cstring>
#include <cuda_runtime.h>
#include "handshake_data.h"
//#include "crypto_kernels.cu"

#define PASSWORD_LENGTH 5
#define THREADS_PER_BLOCK 256

__global__ void brute_force_mic(bool* found, char* result);
__global__ void test_known_password(bool* found, char* result);

int main() {
    char* d_result;
    bool* d_found;

    cudaMalloc(&d_result, PASSWORD_LENGTH + 1);
    cudaMalloc(&d_found, sizeof(bool));
    cudaMemset(d_found, 0, sizeof(bool));

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    // Pokretanje pravog brute-force MIC validacionog kernela
    test_known_password<<<1, 1>>>(d_found, d_result);

    //brute_force_mic<<<400, THREADS_PER_BLOCK>>>(d_found, d_result);
    cudaDeviceSynchronize();

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);

    bool h_found;
    char h_result[PASSWORD_LENGTH + 1] = {0};

    cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_result, d_result, PASSWORD_LENGTH, cudaMemcpyDeviceToHost);

    std::cout << "\n========== STATISTIKA ==========" << std::endl;
    std::cout << "Status: " << (h_found ? "Lozinka pronađena" : "Nije pronađena") << std::endl;
    if (h_found)
        std::cout << "Lozinka: " << h_result << std::endl;
    std::cout << "Vrijeme:  " << milliseconds << " ms" << std::endl;
    std::cout << "================================\n" << std::endl;

    cudaFree(d_result);
    cudaFree(d_found);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    return 0;
}