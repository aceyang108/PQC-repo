#include <stdint.h>

#define Q 8380417

// Standard Cooley-Tukey NTT
// coeffs is an array of 256 elements
// zetas is an array of ntt_zetas
void c_to_ntt(int32_t *coeffs, const int32_t *zetas) {
    int k = 0;
    int l = 128;
    while (l > 0) {
        int start = 0;
        while (start < 256) {
            k = k + 1;
            int32_t zeta = zetas[k];
            for (int j = start; j < start + l; j++) {
                int64_t t = (int64_t)zeta * coeffs[j + l];
                t = t % Q;
                coeffs[j + l] = (coeffs[j] - t + Q) % Q;
                coeffs[j] = (coeffs[j] + t) % Q;
            }
            start = start + 2 * l;
        }
        l >>= 1;
    }
}

// Standard Gentleman-Sande iNTT (from_ntt)
// coeffs is an array of 256 elements
// zetas is an array of ntt_zetas
// ntt_f is the scaling factor
void c_from_ntt(int32_t *coeffs, const int32_t *zetas, int32_t ntt_f) {
    int l = 1;
    int k = 256;
    while (l < 256) {
        int start = 0;
        while (start < 256) {
            k = k - 1;
            int32_t zeta = -zetas[k];
            for (int j = start; j < start + l; j++) {
                int32_t t = coeffs[j];
                coeffs[j] = (t + coeffs[j + l]) % Q;
                coeffs[j + l] = (t - coeffs[j + l] + Q) % Q;
                int64_t tmp = (int64_t)zeta * coeffs[j + l];
                coeffs[j + l] = (tmp % Q + Q) % Q;
            }
            start = start + 2 * l;
        }
        l = l << 1;
    }
    for (int j = 0; j < 256; j++) {
        int64_t tmp = (int64_t)coeffs[j] * ntt_f;
        coeffs[j] = (tmp % Q + Q) % Q;
    }
}

// Coefficient-wise multiplication
void c_ntt_coefficient_multiplication(int32_t *res, const int32_t *f, const int32_t *g) {
    for (int i = 0; i < 256; i++) {
        int64_t tmp = (int64_t)f[i] * g[i];
        res[i] = (tmp % Q + Q) % Q;
    }
}
