#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>

#define SSID "DARKSIDE"
#define SSID_LEN 8
#define MIC_OFFSET 0x81
#define EAPOL_LEN 121
#define SHA1_BLOCK_SIZE 20
#define SHA1_PAD_SIZE 64
#define MIN(a,b) ((a)<(b)?(a):(b))

__device__ const unsigned char bssid[6] = { 0xc4, 0xe9, 0x84, 0xa6, 0x11, 0xe8 };
__device__ const unsigned char client_mac[6] = { 0xaa, 0xbb, 0xde, 0x1d, 0x2f, 0x2a };
__device__ const unsigned char anonce[32] = {
    0x77, 0xaa, 0x3e, 0xfc, 0x09, 0x7d, 0x5a, 0x84, 0xd9, 0x66, 0x00, 0xc2, 0x30, 0x0f, 0x7e, 0xd2,
    0x5c, 0x57, 0x72, 0xce, 0xee, 0x6e, 0x90, 0x47, 0x5e, 0xe7, 0x13, 0x51, 0x2d, 0xdb, 0xa5, 0x26
};
__device__ const unsigned char snonce[32] = {
    0xd5, 0x23, 0x33, 0xb1, 0xe6, 0xca, 0xfe, 0x88, 0xce, 0x95, 0x99, 0x50, 0x8e, 0x18, 0x80, 0xd9,
    0xdc, 0xd1, 0xcf, 0xb4, 0x42, 0x53, 0xb3, 0xf4, 0x4d, 0x6c, 0x8b, 0x45, 0x5c, 0x4b, 0x3d, 0xde
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
__device__ const unsigned char mic[16] = {
    0x42, 0x68, 0x25, 0xf7, 0xa1, 0x2d, 0x8b, 0x99,
    0xef, 0x0a, 0x32, 0x14, 0x61, 0xab, 0x7c, 0xdd
};

__device__ void sha1_cuda(const unsigned char* message, int len, unsigned char* digest) {
    // SHA1 hash implementation (minimal, 1-block message only)
    unsigned int h0 = 0x67452301;
    unsigned int h1 = 0xEFCDAB89;
    unsigned int h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476;
    unsigned int h4 = 0xC3D2E1F0;

    unsigned char msg[64] = {0};
    for (int i = 0; i < len; i++) msg[i] = message[i];
    msg[len] = 0x80;
    unsigned long long bit_len = len * 8;
    for (int i = 0; i < 8; i++) msg[56 + i] = (bit_len >> (56 - 8 * i)) & 0xff;

    unsigned int w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (msg[i*4]<<24) | (msg[i*4+1]<<16) | (msg[i*4+2]<<8) | msg[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = (w[i-3]^w[i-8]^w[i-14]^w[i-16]);
        w[i] = (w[i]<<1) | (w[i]>>31);
    }

    unsigned int a=h0,b=h1,c=h2,d=h3,e=h4;
    for (int i = 0; i < 80; i++) {
        unsigned int f,k;
        if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;            k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;            k = 0xCA62C1D6; }
        unsigned int temp = ((a<<5)|(a>>27)) + f + e + k + w[i];
        e = d;
        d = c;
        c = (b<<30) | (b>>2);
        b = a;
        a = temp;
    }

    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    digest[0] = (h0>>24)&0xff; digest[1] = (h0>>16)&0xff; digest[2] = (h0>>8)&0xff; digest[3] = h0&0xff;
    digest[4] = (h1>>24)&0xff; digest[5] = (h1>>16)&0xff; digest[6] = (h1>>8)&0xff; digest[7] = h1&0xff;
    digest[8] = (h2>>24)&0xff; digest[9] = (h2>>16)&0xff; digest[10] = (h2>>8)&0xff; digest[11] = h2&0xff;
    digest[12] = (h3>>24)&0xff; digest[13] = (h3>>16)&0xff; digest[14] = (h3>>8)&0xff; digest[15] = h3&0xff;
    digest[16] = (h4>>24)&0xff; digest[17] = (h4>>16)&0xff; digest[18] = (h4>>8)&0xff; digest[19] = h4&0xff;
}

__device__ void hmac_sha1_cuda(const unsigned char* key, int key_len, const unsigned char* msg, int msg_len, unsigned char* out_digest) {
    unsigned char k_ipad[SHA1_PAD_SIZE], k_opad[SHA1_PAD_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) {
        k_ipad[i] = (i < key_len ? key[i] : 0x00) ^ 0x36;
        k_opad[i] = (i < key_len ? key[i] : 0x00) ^ 0x5c;
    }

    unsigned char inner[SHA1_PAD_SIZE + 512];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) inner[i] = k_ipad[i];
    for (int i = 0; i < msg_len; i++) inner[SHA1_PAD_SIZE + i] = msg[i];

    unsigned char inner_hash[SHA1_BLOCK_SIZE];
    sha1_cuda(inner, SHA1_PAD_SIZE + msg_len, inner_hash);

    unsigned char outer[SHA1_PAD_SIZE + SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) outer[i] = k_opad[i];
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) outer[SHA1_PAD_SIZE + i] = inner_hash[i];

    sha1_cuda(outer, SHA1_PAD_SIZE + SHA1_BLOCK_SIZE, out_digest);
}

__device__ void pbkdf2_sha1_cuda(const char* pass, int pass_len, const unsigned char* ssid, int ssid_len, unsigned char* output, int dklen) {
    int blocks = (dklen + SHA1_BLOCK_SIZE - 1) / SHA1_BLOCK_SIZE;
    for (int b = 1; b <= blocks; b++) {
        unsigned char U[SHA1_BLOCK_SIZE], T[SHA1_BLOCK_SIZE], msg[36];
        for (int i = 0; i < ssid_len; i++) msg[i] = ssid[i];
        msg[ssid_len + 0] = 0x00; msg[ssid_len + 1] = 0x00; msg[ssid_len + 2] = 0x00; msg[ssid_len + 3] = b;
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
        const int label_len = 22;
        for (int i = 0; i < label_len; i++) input[len++] = label[i];
        input[len++] = 0x00;
        for (int i = 0; i < data_len; i++) input[len++] = data[i];
        input[len++] = counter;
        hmac_sha1_cuda(key, key_len, input, len, digest);
        int copy_len = MIN(SHA1_BLOCK_SIZE, out_len - pos);
        for (int i = 0; i < copy_len; i++) out[pos + i] = digest[i];
        pos += copy_len;
        counter++;
    }
}


___global__ void test_mic_validation(bool* found) {
    const char* password = "12345678";
    const int pass_len = 8;

    unsigned char pmk[32];
    pbkdf2_sha1_cuda(password, pass_len, (const unsigned char*)SSID, SSID_LEN, pmk, 32);

    unsigned char data[128];
    int offset = 0;
    const char* label = "Pairwise key expansion";

    const unsigned char* min_bc = (memcmp(bssid, client_mac, 6) < 0) ? bssid : client_mac;
    const unsigned char* max_bc = (min_bc == bssid) ? client_mac : bssid;
    const unsigned char* min_ns = (memcmp(anonce, snonce, 32) < 0) ? anonce : snonce;
    const unsigned char* max_ns = (min_ns == anonce) ? snonce : anonce;

    memcpy(data + offset, min_bc, 6); offset += 6;
    memcpy(data + offset, max_bc, 6); offset += 6;
    memcpy(data + offset, min_ns, 32); offset += 32;
    memcpy(data + offset, max_ns, 32); offset += 32;

    unsigned char ptk[64];
    prf_cuda(pmk, 32, label, data, offset, ptk, 64);

    unsigned char tmp_eapol[512];
    for (int i = 0; i < EAPOL_LEN; i++) tmp_eapol[i] = eapol[i];
    for (int i = MIC_OFFSET; i < MIC_OFFSET + 16; i++) tmp_eapol[i] = 0x00;

    unsigned char calc_mic[SHA1_BLOCK_SIZE];
    hmac_sha1_cuda(ptk, 16, tmp_eapol, EAPOL_LEN, calc_mic);

    printf("Računat MIC: ");
    for (int i = 0; i < 16; i++) printf("%02x", calc_mic[i]);
    printf("\n");

    printf("Očekivani MIC: ");
    for (int i = 0; i < 16; i++) printf("%02x", mic[i]);
    printf("\n");

    bool match = true;
    for (int i = 0; i < 16; i++) {
        if (calc_mic[i] != mic[i]) {
            printf("Mismatch at byte %d: got %02x, expected %02x\n", i, calc_mic[i], mic[i]);
            match = false;
            break;
        }
    }

    if (match) *found = true;
}

int main() {
    bool* d_found;
    bool h_found = false;
    cudaMalloc(&d_found, sizeof(bool));
    cudaMemcpy(d_found, &h_found, sizeof(bool), cudaMemcpyHostToDevice);

    test_mic_validation<<<1, 1>>>(d_found);
    cudaDeviceSynchronize();

    cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    printf("\nMIC validacija: %s\n", h_found ? "USPJESNA" : "NEUSPJESNA");
    cudaFree(d_found);
    return 0;
}