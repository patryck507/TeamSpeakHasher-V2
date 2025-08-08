#include <cuda_runtime.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <stdint.h>
#include <cstdlib>

#define CUDA_CHECK(expr)                                                         \
    do {                                                                        \
        cudaError_t err = (expr);                                               \
        if (err != cudaSuccess) {                                               \
            std::cerr << "CUDA error: " << cudaGetErrorString(err)             \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl;\
            std::exit(1);                                                       \
        }                                                                       \
    } while (0)

// Use constant memory for the SHA1 round constants for faster access
__constant__ uint32_t k[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

__device__ inline uint32_t ROTLEFT(uint32_t a, uint32_t b) {
    return (a << b) | (a >> (32 - b));
}

// Core SHA1 transform operating on a single 64 byte block
__device__ void sha1_transform(uint32_t state[5], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, i, j, t, m[80];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    for (; i < 80; ++i) {
        m[i] = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
        m[i] = (m[i] << 1) | (m[i] >> 31);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 20; ++i) {
        t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + k[0] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for (; i < 40; ++i) {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + k[1] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for (; i < 60; ++i) {
        t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + k[2] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for (; i < 80; ++i) {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + k[3] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

// Kernel expects messages shorter than 56 bytes
__global__ void sha1_kernel(const uint8_t *input, size_t len, uint8_t *hash) {
    __shared__ uint8_t sdata[64]; // shared memory for faster access
    int tid = threadIdx.x;
    if (tid < len) sdata[tid] = input[tid];
    __syncthreads();

    if (tid == 0) {
        // pad remaining bytes
        sdata[len] = 0x80;
        for (size_t i = len + 1; i < 56; ++i) sdata[i] = 0;
        uint64_t bitlen = len * 8;
        for (int i = 0; i < 8; ++i) sdata[63 - i] = bitlen >> (8 * i);

        uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        sha1_transform(state, sdata);
        for (int i = 0; i < 5; ++i) {
            hash[i * 4 + 0] = (state[i] >> 24) & 0xff;
            hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
            hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
            hash[i * 4 + 3] = state[i] & 0xff;
        }
    }
}

// Host helper wrapping the kernel
void sha1_cuda(const std::string &input, std::vector<uint8_t> &output) {
    uint8_t *d_in = nullptr, *d_out = nullptr;
    size_t len = input.size();
    CUDA_CHECK(cudaMalloc(&d_in, len ? len : 1)); // allocate at least 1 byte
    CUDA_CHECK(cudaMalloc(&d_out, 20));
    if (len)
        CUDA_CHECK(cudaMemcpy(d_in, input.data(), len, cudaMemcpyHostToDevice));
    sha1_kernel<<<1, 64>>>(d_in, len, d_out);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(output.data(), d_out, 20, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

std::string to_hex(const std::vector<uint8_t> &hash) {
    std::ostringstream oss;
    for (auto b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

bool run_test(const std::string &msg, const std::string &expected) {
    std::vector<uint8_t> out(20);
    sha1_cuda(msg, out);
    std::string hex = to_hex(out);
    bool ok = (hex == expected);
    std::cout << "SHA1('" << msg << "') = " << hex
              << (ok ? " [OK]" : " [FAIL]") << std::endl;
    return ok;
}

int main() {
    bool all_ok = true;
    all_ok &= run_test("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    all_ok &= run_test("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    return all_ok ? 0 : 1;
}
