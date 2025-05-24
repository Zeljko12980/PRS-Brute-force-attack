#include <stdio.h>
#include <string.h>
#include "handshake_data.h"

#define SHA1_BLOCK_SIZE 20
#define SHA1_PAD_SIZE 64
#define MIN(a,b) ((a)<(b)?(a):(b))

__device__ void sha1_cuda(const unsigned char* message, int len, unsigned char* digest) {
    unsigned int h0 = 0x67452301;
    unsigned int h1 = 0xEFCDAB89;
    unsigned int h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476;
    unsigned int h4 = 0xC3D2E1F0;

    int new_len = len + 1;
    while ((new_len % 64) != 56) new_len++;

    unsigned char msg[64] = {0};
    for (int i = 0; i < len && i < 64; i++) msg[i] = message[i];
    msg[len] = 0x80;

    unsigned long long bit_len = len * 8;
    for (int i = 0; i < 8; i++) msg[56 + i] = (bit_len >> (56 - 8 * i)) & 0xff;

    unsigned int w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (msg[i * 4 + 0] << 24) |
               (msg[i * 4 + 1] << 16) |
               (msg[i * 4 + 2] << 8)  |
               (msg[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        unsigned int temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (temp << 1) | (temp >> 31);
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
    digest[0] = (h0 >> 24) & 0xff; digest[1] = (h0 >> 16) & 0xff; digest[2] = (h0 >> 8) & 0xff; digest[3] = h0 & 0xff;
    digest[4] = (h1 >> 24) & 0xff; digest[5] = (h1 >> 16) & 0xff; digest[6] = (h1 >> 8) & 0xff; digest[7] = h1 & 0xff;
    digest[8] = (h2 >> 24) & 0xff; digest[9] = (h2 >> 16) & 0xff; digest[10] = (h2 >> 8) & 0xff; digest[11] = h2 & 0xff;
    digest[12] = (h3 >> 24) & 0xff; digest[13] = (h3 >> 16) & 0xff; digest[14] = (h3 >> 8) & 0xff; digest[15] = h3 & 0xff;
    digest[16] = (h4 >> 24) & 0xff; digest[17] = (h4 >> 16) & 0xff; digest[18] = (h4 >> 8) & 0xff; digest[19] = h4 & 0xff;
}

__device__ const unsigned char* min_bytes(const unsigned char* a, const unsigned char* b, int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return (a[i] < b[i]) ? a : b;
    return a;
}

__device__ const unsigned char* max_bytes(const unsigned char* a, const unsigned char* b, int len) {
    for (int i = 0; i < len; i++) if (a[i] != b[i]) return (a[i] > b[i]) ? a : b;
    return a;
}

__device__ void hmac_sha1_cuda(const unsigned char* key, int key_len, const unsigned char* msg, int msg_len, unsigned char* out_digest) {
    unsigned char ipad[SHA1_PAD_SIZE], opad[SHA1_PAD_SIZE], key_pad[SHA1_PAD_SIZE], inner[SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) {
        key_pad[i] = (i < key_len) ? key[i] : 0x00;
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    unsigned char inner_buf[SHA1_PAD_SIZE + 64];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) inner_buf[i] = ipad[i];
    for (int i = 0; i < msg_len; i++) inner_buf[SHA1_PAD_SIZE + i] = msg[i];
    sha1_cuda(inner_buf, SHA1_PAD_SIZE + msg_len, inner);

    unsigned char outer_buf[SHA1_PAD_SIZE + SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_PAD_SIZE; i++) outer_buf[i] = opad[i];
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) outer_buf[SHA1_PAD_SIZE + i] = inner[i];
    sha1_cuda(outer_buf, SHA1_PAD_SIZE + SHA1_BLOCK_SIZE, out_digest);
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
        for (int j = 0; j < SHA1_BLOCK_SIZE && (j + (b - 1) * SHA1_BLOCK_SIZE) < dklen; j++) output[(b - 1) * SHA1_BLOCK_SIZE + j] = T[j];
    }
}

__device__ void prf_cuda(const unsigned char* key, int key_len, const char* label, const unsigned char* data, int data_len, unsigned char* out, int out_len) {
    int pos = 0, counter = 0x01;
    unsigned char digest[SHA1_BLOCK_SIZE];
    while (pos < out_len) {
        unsigned char input[128];
        int len = 0;
        const int label_len = 22; // strlen("Pairwise key expansion")
        for (int i = 0; i < label_len; i++) input[i] = label[i];
        len += label_len;
        input[len++] = 0x00;
        for (int i = 0; i < data_len; i++) input[len + i] = data[i];
        len += data_len;
        input[len++] = counter;
        hmac_sha1_cuda(key, key_len, input, len, digest);
        int copy_len = MIN(SHA1_BLOCK_SIZE, out_len - pos);
        for (int i = 0; i < copy_len; i++) out[pos + i] = digest[i];
        pos += copy_len; counter++;
    }
}

__device__ bool validate_mic(const unsigned char* ptk, const unsigned char* eapol_frame, int eapol_len, const unsigned char* expected_mic) {
    unsigned char calc_mic[SHA1_BLOCK_SIZE], tmp_eapol[256];
    for (int i = 0; i < eapol_len; i++) tmp_eapol[i] = eapol_frame[i];
    for (int i = 0x59; i < 0x59 + 16; i++) tmp_eapol[i] = 0x00;
    hmac_sha1_cuda(ptk, 16, tmp_eapol, eapol_len, calc_mic);
    for (int i = 0; i < 16; i++) if (calc_mic[i] != expected_mic[i]) return false;
    return true;
}

__global__ void brute_force_mic(bool* found, char* result) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (*found || idx >= 100000) return;

    char password[6];
    password[0] = '0' + (idx / 10000) % 10;
    password[1] = '0' + (idx / 1000) % 10;
    password[2] = '0' + (idx / 100) % 10;
    password[3] = '0' + (idx / 10) % 10;
    password[4] = '0' + (idx % 10);
    password[5] = '\0';

    unsigned char pmk[32];
    pbkdf2_sha1_cuda(password, 5, (const unsigned char*)SSID, SSID_LEN, pmk, 32);

    unsigned char data[128];
    int offset = 0;
    const char* label = "Pairwise key expansion";
    const unsigned char* min_bssid_client = min_bytes(bssid, client_mac, 6);
    const unsigned char* max_bssid_client = max_bytes(bssid, client_mac, 6);
    const unsigned char* min_anonce_snonce = min_bytes(anonce, snonce, 32);
    const unsigned char* max_anonce_snonce = max_bytes(anonce, snonce, 32);

    for (int i = 0; i < 6; i++) data[offset + i] = min_bssid_client[i];
    offset += 6;
    for (int i = 0; i < 6; i++) data[offset + i] = max_bssid_client[i];
    offset += 6;
    for (int i = 0; i < 32; i++) data[offset + i] = min_anonce_snonce[i];
    offset += 32;
    for (int i = 0; i < 32; i++) data[offset + i] = max_anonce_snonce[i];
    offset += 32;

    unsigned char ptk[64];
    prf_cuda(pmk, 32, label, data, offset, ptk, 64);
    if (validate_mic(ptk, eapol, EAPOL_LEN, mic)) {
        *found = true;
        for (int i = 0; i < 5; i++) result[i] = password[i];
    }
}

__global__ void test_known_password(bool* found, char* result) {
    const char* password = "244466666";
    const int pass_len = 9;

    unsigned char pmk[32];
    pbkdf2_sha1_cuda(password, pass_len, (const unsigned char*)SSID, SSID_LEN, pmk, 32);

    unsigned char data[128];
    int offset = 0;
    const char* label = "Pairwise key expansion";

    const unsigned char* min_bssid_client = min_bytes(bssid, client_mac, 6);
    const unsigned char* max_bssid_client = max_bytes(bssid, client_mac, 6);
    const unsigned char* min_anonce_snonce = min_bytes(anonce, snonce, 32);
    const unsigned char* max_anonce_snonce = max_bytes(anonce, snonce, 32);

    for (int i = 0; i < 6; i++) data[offset + i] = min_bssid_client[i];
    offset += 6;
    for (int i = 0; i < 6; i++) data[offset + i] = max_bssid_client[i];
    offset += 6;
    for (int i = 0; i < 32; i++) data[offset + i] = min_anonce_snonce[i];
    offset += 32;
    for (int i = 0; i < 32; i++) data[offset + i] = max_anonce_snonce[i];
    offset += 32;

    unsigned char ptk[64];
    prf_cuda(pmk, 32, label, data, offset, ptk, 64);

    unsigned char calc_mic[SHA1_BLOCK_SIZE];
    unsigned char tmp_eapol[256];
    for (int i = 0; i < EAPOL_LEN; i++) tmp_eapol[i] = eapol[i];
    for (int i = 0x59; i < 0x59 + 16; i++) tmp_eapol[i] = 0x00;  // MIC offset
    hmac_sha1_cuda(ptk, 16, tmp_eapol, EAPOL_LEN, calc_mic);

    // Ispis izračunatog MIC-a
    printf("Računat MIC: ");
    for (int i = 0; i < 16; i++) printf("%02x", calc_mic[i]);
    printf("\n");

    printf("Očekivani MIC: ");
    for (int i = 0; i < 16; i++) printf("%02x", mic[i]);
    printf("\n");

    bool match = true;
    for (int i = 0; i < 16; i++) {
        if (calc_mic[i] != mic[i]) {
            match = false;
            break;
        }
    }

    if (match) {
        *found = true;
        for (int i = 0; i < pass_len; i++) result[i] = password[i];
        result[pass_len] = '\0';
    }
}