import secrets
import hashlib
import struct
import time
import os

# Try to import optional high-performance libraries
try:
    import oqs
    # Trigger a dry-run to ensure the pre-compiled C-library DLL actually loads successfully
    _t = oqs.Signature("ML-DSA-44")
    HAS_LIBOQS = True
except BaseException:
    # Graceful fallback if oqs Python package is installed but the DLL is missing or failed to compile
    HAS_LIBOQS = False

from OBU.signature import (
    G, N, P, A, B, Gx, Gy, Point, INFINITY,
    mod_inv, point_add, point_double, point_mul,
    point_to_bytes, bytes_to_point, ecqv_hash,
    h_fswa_sign, h_fswa_verify
)
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
from dilithium_py.polynomials.polynomials import Polynomial, PolynomialNTT
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Define Multi-Backend Modes
MODE_PURE_PYTHON = 0      # Mode 0: Current Pure-Python (Silithium H-FSwA + ECQV)
MODE_NUMBA_JIT = 1        # Mode 1: Numba JIT-Accelerated (Silithium H-FSwA + ECQV)
MODE_LIBOQS_PARALLEL = 2  # Mode 2: Official liboqs C-Library (Parallel ECDSA + ML-DSA)
MODE_CUSTOM_C = 3         # Mode 3: Custom C-Backend (Silithium H-FSwA + ECQV)

# Current active mode (User can change this to switch backends)
ACTIVE_MODE = MODE_PURE_PYTHON

# --- Store original pure Python implementation before monkey-patching ---
ORIGINAL_TO_NTT = Polynomial.to_ntt
ORIGINAL_FROM_NTT = PolynomialNTT.from_ntt
ORIGINAL_NTT_MULTIPLICATION = PolynomialNTT.ntt_multiplication

# --- Custom C Backend ctypes Loading ---
import ctypes
CUSTOM_C_LIB = None
HAS_CUSTOM_C = False

try:
    # Look for DLL/SO inside C_Backend directory relative to signature_oqs.py
    current_dir = os.path.dirname(os.path.abspath(__file__))
    c_backend_dir = os.path.abspath(os.path.join(current_dir, "..", "C_Backend"))
    
    if os.name == 'nt':
        dll_name = "ntt.dll"
    else:
        dll_name = "ntt.so"
        
    dll_path = os.path.join(c_backend_dir, dll_name)
    
    if os.path.exists(dll_path):
        CUSTOM_C_LIB = ctypes.CDLL(dll_path)
    else:
        # Fallback to current directory or system path search
        CUSTOM_C_LIB = ctypes.CDLL(dll_name)
        
    # Define ctypes function signatures
    CUSTOM_C_LIB.c_to_ntt.argtypes = [
        ctypes.POINTER(ctypes.c_int32),  # coeffs
        ctypes.POINTER(ctypes.c_int32)   # zetas
    ]
    CUSTOM_C_LIB.c_to_ntt.restype = None

    CUSTOM_C_LIB.c_from_ntt.argtypes = [
        ctypes.POINTER(ctypes.c_int32),  # coeffs
        ctypes.POINTER(ctypes.c_int32),  # zetas
        ctypes.c_int32                   # ntt_f
    ]
    CUSTOM_C_LIB.c_from_ntt.restype = None

    CUSTOM_C_LIB.c_ntt_coefficient_multiplication.argtypes = [
        ctypes.POINTER(ctypes.c_int32),  # res
        ctypes.POINTER(ctypes.c_int32),  # f
        ctypes.POINTER(ctypes.c_int32)   # g
    ]
    CUSTOM_C_LIB.c_ntt_coefficient_multiplication.restype = None
    
    HAS_CUSTOM_C = True
except Exception:
    HAS_CUSTOM_C = False

# Patched methods using Custom C-Backend
def c_to_ntt_patch(self):
    c_arr = (ctypes.c_int32 * 256)(*self.coeffs)
    zetas_arr = (ctypes.c_int32 * 256)(*self.parent.ntt_zetas)
    CUSTOM_C_LIB.c_to_ntt(c_arr, zetas_arr)
    return self.parent(list(c_arr), is_ntt=True)

def c_from_ntt_patch(self):
    c_arr = (ctypes.c_int32 * 256)(*self.coeffs)
    zetas_arr = (ctypes.c_int32 * 256)(*self.parent.ntt_zetas)
    CUSTOM_C_LIB.c_from_ntt(c_arr, zetas_arr, self.parent.ntt_f)
    return self.parent(list(c_arr), is_ntt=False)

def c_ntt_multiplication_patch(self, other):
    if not isinstance(other, type(self)):
        raise ValueError
    res_arr = (ctypes.c_int32 * 256)()
    f_arr = (ctypes.c_int32 * 256)(*self.coeffs)
    g_arr = (ctypes.c_int32 * 256)(*other.coeffs)
    CUSTOM_C_LIB.c_ntt_coefficient_multiplication(res_arr, f_arr, g_arr)
    return list(res_arr)


# --- Numba JIT Backend Implementation ---
HAS_NUMBA = False
try:
    import numba
    import numpy as np
    from numba import njit
    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False

if HAS_NUMBA:
    # Numba JIT-Compiled Cooley-Tukey NTT
    @njit(fastmath=True, cache=True)
    def numba_to_ntt_core(coeffs, zetas):
        k = 0
        l = 128
        while l > 0:
            start = 0
            while start < 256:
                k = k + 1
                zeta = zetas[k]
                j = start
                for j in range(start, start + l):
                    t = (zeta * coeffs[j + l]) % 8380417
                    coeffs[j + l] = (coeffs[j] - t + 8380417) % 8380417
                    coeffs[j] = (coeffs[j] + t) % 8380417
                start = l + (j + 1)
            l >>= 1
        return coeffs

    # Numba JIT-Compiled Gentleman-Sande Inverse NTT
    @njit(fastmath=True, cache=True)
    def numba_from_ntt_core(coeffs, zetas, ntt_f):
        l = 1
        k = 256
        while l < 256:
            start = 0
            while start < 256:
                k = k - 1
                zeta = -zetas[k]
                j = start
                for j in range(start, start + l):
                    t = coeffs[j]
                    coeffs[j] = (t + coeffs[j + l]) % 8380417
                    coeffs[j + l] = (t - coeffs[j + l] + 8380417) % 8380417
                    coeffs[j + l] = (zeta * coeffs[j + l]) % 8380417
                start = j + l + 1
            l = l << 1
        for j in range(256):
            coeffs[j] = (coeffs[j] * ntt_f) % 8380417
        return coeffs

    @njit(fastmath=True, cache=True)
    def numba_coefficient_multiplication_core(f_coeffs, g_coeffs):
        res = np.zeros(256, dtype=np.int32)
        for i in range(256):
            res[i] = (f_coeffs[i] * g_coeffs[i]) % 8380417
        return res

    # Numba patched methods for monkey-patching
    def numba_to_ntt_patch(self):
        c_np = np.array(self.coeffs, dtype=np.int32)
        zetas_np = np.array(self.parent.ntt_zetas, dtype=np.int32)
        res_np = numba_to_ntt_core(c_np, zetas_np)
        return self.parent(res_np.tolist(), is_ntt=True)

    def numba_from_ntt_patch(self):
        c_np = np.array(self.coeffs, dtype=np.int32)
        zetas_np = np.array(self.parent.ntt_zetas, dtype=np.int32)
        res_np = numba_from_ntt_core(c_np, zetas_np, self.parent.ntt_f)
        return self.parent(res_np.tolist(), is_ntt=False)

    def numba_ntt_multiplication_patch(self, other):
        if not isinstance(other, type(self)):
            raise ValueError
        f_np = np.array(self.coeffs, dtype=np.int32)
        g_np = np.array(other.coeffs, dtype=np.int32)
        res_np = numba_coefficient_multiplication_core(f_np, g_np)
        return res_np.tolist()


# --- Apply Backend Function ---
def apply_backend(mode):
    global ACTIVE_MODE
    ACTIVE_MODE = mode
    if mode == MODE_PURE_PYTHON:
        Polynomial.to_ntt = ORIGINAL_TO_NTT
        PolynomialNTT.from_ntt = ORIGINAL_FROM_NTT
        PolynomialNTT.ntt_multiplication = ORIGINAL_NTT_MULTIPLICATION
    elif mode == MODE_NUMBA_JIT:
        if HAS_NUMBA:
            Polynomial.to_ntt = numba_to_ntt_patch
            PolynomialNTT.from_ntt = numba_from_ntt_patch
            PolynomialNTT.ntt_multiplication = numba_ntt_multiplication_patch
        else:
            print("\033[1;33m[警告] 未能加載 Numba，自動降級為純 Python 模式！\033[0m")
            ACTIVE_MODE = MODE_PURE_PYTHON
            Polynomial.to_ntt = ORIGINAL_TO_NTT
            PolynomialNTT.from_ntt = ORIGINAL_FROM_NTT
            PolynomialNTT.ntt_multiplication = ORIGINAL_NTT_MULTIPLICATION
    elif mode == MODE_CUSTOM_C:
        if HAS_CUSTOM_C:
            Polynomial.to_ntt = c_to_ntt_patch
            PolynomialNTT.from_ntt = c_from_ntt_patch
            PolynomialNTT.ntt_multiplication = c_ntt_multiplication_patch
        else:
            print("\033[1;33m[警告] 未能載入客製化 C NTT 庫 (ntt.dll/ntt.so)，自動降級為純 Python 模式！\033[0m")
            ACTIVE_MODE = MODE_PURE_PYTHON
            Polynomial.to_ntt = ORIGINAL_TO_NTT
            PolynomialNTT.from_ntt = ORIGINAL_FROM_NTT
            PolynomialNTT.ntt_multiplication = ORIGINAL_NTT_MULTIPLICATION


# --- Mode 2: Official liboqs Parallel Hybrid Signatures ---
def liboqs_parallel_sign(obu_id, private_key_pem_path, pqc_sk_path, message):
    """
    Parallel Hybrid Signing:
    1. ECC: Standard ECDSA signature on SECP256R1 curve (via OpenSSL C backend)
    2. PQC: Standard ML-DSA-44 signature (via liboqs C library)
    Output: 64-byte ECDSA signature + 2420-byte PQC signature = 2484 bytes.
    """
    if not HAS_LIBOQS:
        print("\033[1;31m[警告] 本機尚未安裝 liboqs，自動降級為純 Python H-FSwA 簽章！\033[0m")
        # Fallback to Mode 0
        with open(f"OBU/keys/{obu_id}_ecc_priv.key", "rb") as f:
            d_ecc = int.from_bytes(f.read(), 'big')
        with open(pqc_sk_path, "rb") as f:
            sk_pqc = f.read()
        return h_fswa_sign(sk_pqc, d_ecc, message)

    # 1. ECC Signing using OpenSSL C Backend (via cryptography library)
    with open(private_key_pem_path, "rb") as key_file:
        private_key = ec.derive_private_key(
            int.from_bytes(key_file.read(), 'big'),
            ec.SECP256R1()
        )
    sig_ecc = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    
    # Standardize ECDSA signature to 64 bytes (R, S integers)
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig_ecc)
    sig_ecc_raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')  # 64 bytes

    # 2. PQC Signing using liboqs C-Library
    with open(pqc_sk_path, "rb") as f:
        sk_pqc = f.read()
        
    signer = oqs.Signature("ML-DSA-44")
    sig_pqc = signer.sign(message, sk_pqc)  # 2420 bytes

    # Total hybrid signature: 64 + 2420 = 2484 bytes
    return sig_ecc_raw + sig_pqc


def liboqs_parallel_verify(obu_id, Q_point, pk_obu_pqc, message, sig_hybrid):
    """
    Parallel Hybrid Verification:
    Verifies BOTH standard ECDSA (via OpenSSL) and ML-DSA-44 (via liboqs).
    """
    if len(sig_hybrid) != 2484:
        return False

    sig_ecc_raw = sig_hybrid[:64]
    sig_pqc = sig_hybrid[64:]

    # 1. Verify ECC ECDSA Signature using cryptography (OpenSSL C backend)
    r = int.from_bytes(sig_ecc_raw[:32], 'big')
    s = int.from_bytes(sig_ecc_raw[32:], 'big')
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    sig_ecc_der = encode_dss_signature(r, s)

    try:
        public_numbers = ec.EllipticCurvePublicNumbers(Q_point.x, Q_point.y, ec.SECP256R1())
        public_key = public_numbers.public_key()
        public_key.verify(sig_ecc_der, message, ec.ECDSA(hashes.SHA256()))
        ecc_passed = True
    except Exception:
        ecc_passed = False

    if not ecc_passed:
        return False

    # 2. Verify PQC ML-DSA-44 Signature using liboqs
    if not HAS_LIBOQS:
        # Graceful fallback: verify using our pure Python ML-DSA verify
        try:
            passed = ML_DSA_44.verify(pk_obu_pqc, message, sig_pqc)
            return passed
        except Exception:
            return False

    try:
        verifier = oqs.Signature("ML-DSA-44")
        pqc_passed = verifier.verify(message, sig_pqc, pk_obu_pqc)
        return pqc_passed
    except Exception:
        return False


# --- Master Wrapper Interfaces ---
def json_encode_bytes(data):
    import json
    return json.dumps(data).encode('utf-8')


def master_sign(obu_id, known_RSU=False):
    """
    Master signing interface that automatically respects the active MODE.
    """
    from OBU.gen_payload import generate_bsm_payload
    payload = generate_bsm_payload(obu_id)
    message = json_encode_bytes(payload)

    # Load keys
    ecc_priv_path = f"OBU/keys/{obu_id}_ecc_priv.key"
    pqc_priv_path = f"OBU/keys/{obu_id}_pqc_priv.key"

    with open(ecc_priv_path, "rb") as f:
        d_ecc = int.from_bytes(f.read(), 'big')
    with open(pqc_priv_path, "rb") as f:
        sk_pqc = f.read()

    # Apply backend first based on active mode
    apply_backend(ACTIVE_MODE)

    # Select Mode
    if ACTIVE_MODE == MODE_LIBOQS_PARALLEL and HAS_LIBOQS:
        sig_hybrid = liboqs_parallel_sign(obu_id, ecc_priv_path, pqc_priv_path, message)
        sig_len = 2484
    else:
        # Default/Fallback to H-FSwA (Silithium) with active backend (Mode 0, 1, or 3)
        sig_hybrid = h_fswa_sign(sk_pqc, d_ecc, message)
        sig_len = 2452

    # Load implicit certificate
    cert_suffix = "short_cert.bin" if known_RSU else "full_cert.bin"
    with open(f"OBU/cert/{obu_id}_{cert_suffix}", "rb") as f:
        cert = f.read()

    msg_len = struct.pack('!H', len(message))
    packet = msg_len + message + cert + sig_hybrid
    return packet, len(message), len(cert), sig_len
